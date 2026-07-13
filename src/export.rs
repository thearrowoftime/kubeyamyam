use crate::models::{Finding, RuleId, ScanReport, ScanSummary, Severity};
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::fs;
use std::io::Write;
use std::path::Path;

pub fn build_report(path: &Path, findings: Vec<Finding>) -> ScanReport {
    let summary = ScanSummary::from_findings(&findings);
    ScanReport {
        tool: "kubeyamyam".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        path: path.display().to_string(),
        findings,
        summary,
    }
}

pub fn write_json(report: &ScanReport, out: &mut dyn Write) -> Result<()> {
    serde_json::to_writer_pretty(&mut *out, report)?;
    writeln!(out)?;
    Ok(())
}

pub fn write_text(report: &ScanReport, out: &mut dyn Write) -> Result<()> {
    if report.findings.is_empty() {
        writeln!(out, "No security issues found in {}", report.path)?;
        return Ok(());
    }

    for f in &report.findings {
        let container = f
            .container
            .as_ref()
            .map(|c| format!(" [{c}]"))
            .unwrap_or_default();
        writeln!(
            out,
            "{:<8} {:<18} {}{}",
            f.severity.as_str(),
            f.rule_id.as_str(),
            f.resource,
            container
        )?;
        writeln!(out, "         {}", f.file)?;
        writeln!(out, "         {}", f.message)?;
        writeln!(out)?;
    }

    writeln!(
        out,
        "Total: {} (CRITICAL={}, HIGH={}, MEDIUM={}, LOW={})",
        report.summary.total,
        report.summary.critical,
        report.summary.high,
        report.summary.medium,
        report.summary.low
    )?;
    Ok(())
}

/// SARIF 2.1.0 document suitable for GitHub Code Scanning / CI uploads.
pub fn write_sarif(report: &ScanReport, out: &mut dyn Write) -> Result<()> {
    let rules: Vec<Value> = RuleId::all()
        .iter()
        .map(|r| {
            json!({
                "id": r.as_str(),
                "name": r.label(),
                "shortDescription": { "text": r.label() },
                "fullDescription": { "text": r.label() },
                "helpUri": r.help_uri(),
                "properties": {
                    "tags": ["security", "kubernetes"]
                }
            })
        })
        .collect();

    let results: Vec<Value> = report
        .findings
        .iter()
        .map(|f| {
            let level = match f.severity {
                Severity::Critical | Severity::High => "error",
                Severity::Medium => "warning",
                Severity::Low => "note",
            };
            let uri = path_to_uri(&f.file);
            json!({
                "ruleId": f.rule_id.as_str(),
                "level": level,
                "message": { "text": f.message },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": uri },
                    }
                }],
                "properties": {
                    "severity": f.severity.as_str(),
                    "resource": f.resource,
                    "namespace": f.namespace,
                    "container": f.container,
                }
            })
        })
        .collect();

    let doc = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "kubeyamyam",
                    "version": report.version,
                    "informationUri": "https://github.com/thearrowoftime",
                    "rules": rules
                }
            },
            "results": results
        }]
    });

    serde_json::to_writer_pretty(&mut *out, &doc)?;
    writeln!(out)?;
    Ok(())
}

pub fn write_report_to_path(report: &ScanReport, format: OutputFormat, path: &Path) -> Result<()> {
    let mut file = fs::File::create(path)
        .with_context(|| format!("cannot create {}", path.display()))?;
    match format {
        OutputFormat::Text => write_text(report, &mut file),
        OutputFormat::Json => write_json(report, &mut file),
        OutputFormat::Sarif => write_sarif(report, &mut file),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Json,
    Sarif,
}

fn path_to_uri(path: &str) -> String {
    let p = Path::new(path);
    if let Ok(abs) = p.canonicalize() {
        let s = abs.to_string_lossy().replace('\\', "/");
        if s.starts_with('/') {
            format!("file://{s}")
        } else {
            // Windows: C:/...
            format!("file:///{s}")
        }
    } else {
        path.replace('\\', "/")
    }
}

/// Exit 1 when any finding is at or above `fail_on`.
/// `fail_on = None` means never fail (exit 0 on successful scan).
pub fn exit_code(findings: &[Finding], fail_on: Option<Severity>) -> i32 {
    let Some(threshold) = fail_on else {
        return 0;
    };
    if findings.iter().any(|f| f.severity <= threshold) {
        1
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fail_on_high_trips_on_critical() {
        let findings = vec![Finding {
            severity: Severity::Critical,
            rule_id: RuleId::Privileged,
            file: "a.yaml".into(),
            resource: "Pod/x".into(),
            namespace: "default".into(),
            container: None,
            message: "x".into(),
        }];
        assert_eq!(exit_code(&findings, Some(Severity::High)), 1);
        assert_eq!(exit_code(&findings, Some(Severity::Critical)), 1);
        assert_eq!(exit_code(&findings, None), 0);
    }
}
