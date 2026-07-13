use crate::models::{Finding, RuleId, Severity};
use anyhow::{Context, Result};
use serde_yaml::Value;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

const WORKLOAD_KINDS: &[&str] = &[
    "Pod",
    "Deployment",
    "StatefulSet",
    "DaemonSet",
    "Job",
    "CronJob",
    "ReplicaSet",
];

const POD_TEMPLATE_KINDS: &[&str] = &[
    "Deployment",
    "StatefulSet",
    "DaemonSet",
    "Job",
    "CronJob",
    "ReplicaSet",
];

pub fn collect_manifest_files(target: &Path) -> Result<Vec<PathBuf>> {
    if target.is_file() {
        return Ok(vec![target.to_path_buf()]);
    }
    if !target.is_dir() {
        anyhow::bail!("not a file or directory: {}", target.display());
    }

    let mut files = Vec::new();
    for entry in WalkDir::new(target).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if name.ends_with(".yaml") || name.ends_with(".yml") || name.ends_with(".yaml.j2") {
            files.push(path.to_path_buf());
        }
    }
    files.sort();
    files.dedup();
    Ok(files)
}

pub fn scan_path(target: &Path) -> Result<Vec<Finding>> {
    let files = collect_manifest_files(target)?;
    let mut findings = Vec::new();
    for file in files {
        findings.extend(scan_file(&file)?);
    }
    findings.sort_by(|a, b| {
        a.severity
            .rank()
            .cmp(&b.severity.rank())
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.resource.cmp(&b.resource))
    });
    Ok(findings)
}

fn display_path(path: &Path) -> String {
    let s = path.display().to_string();
    s.strip_prefix(r"\\?\").unwrap_or(&s).to_string()
}

fn looks_like_k8s_manifest(raw: &str) -> bool {
    let has_api = raw.contains("apiVersion:");
    let has_kind = raw.contains("kind:");
    has_api && has_kind
}

/// Replace only bare Jinja *values* after a colon: `key: {{ var }}` → `key: "__jinja__"`.
fn neutralize_jinja_values(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while !rest.is_empty() {
        if let Some(idx) = rest.find(':') {
            out.push_str(&rest[..idx]);
            out.push(':');
            rest = &rest[idx + 1..];
            let trimmed = rest.trim_start_matches([' ', '\t']);
            let ws_len = rest.len() - trimmed.len();
            out.push_str(&rest[..ws_len]);
            rest = trimmed;
            if let Some(inner) = rest.strip_prefix("{{") {
                if let Some(end) = inner.find("}}") {
                    out.push_str("\"__jinja__\"");
                    rest = &inner[end + 2..];
                    continue;
                }
            }
        } else {
            out.push_str(rest);
            break;
        }
    }
    out
}

pub fn scan_file(path: &Path) -> Result<Vec<Finding>> {
    let file_path = display_path(path);
    let raw = fs::read_to_string(path)
        .with_context(|| format!("cannot read {}", path.display()))?;

    if !looks_like_k8s_manifest(&raw) {
        return Ok(Vec::new());
    }

    // Quote bare Jinja values (`image: {{ var }}`) so templates still parse.
    let raw = neutralize_jinja_values(&raw);

    let mut docs: Vec<Value> = Vec::new();
    for document in raw.split("---") {
        let doc = document.trim();
        if doc.is_empty() {
            continue;
        }
        match serde_yaml::from_str::<Value>(doc) {
            Ok(Value::Null) => {}
            Ok(v) if v.is_mapping() => docs.push(v),
            Ok(_) => {}
            Err(_) => continue,
        }
    }

    // Only keep documents that are actually Kubernetes resources.
    docs.retain(|d| map_str(d, &["apiVersion"]).is_some() && map_str(d, &["kind"]).is_some());
    if docs.is_empty() {
        return Ok(Vec::new());
    }

    let mut findings = Vec::new();
    let mut cluster_admin_sas: HashSet<(String, String)> = HashSet::new();

    for doc in &docs {
        findings.extend(scan_document(&file_path, doc));
        findings.extend(scan_bindings(&file_path, doc, &mut cluster_admin_sas));
    }

    for doc in &docs {
        let kind = map_str(doc, &["kind"]).unwrap_or_default();
        if !WORKLOAD_KINDS.contains(&kind.as_str()) {
            continue;
        }
        let resource = resource_label(doc);
        let ns = namespace_of(doc);
        for (_, spec) in iter_pod_specs(doc) {
            let sa = map_str(spec, &["serviceAccountName"]).unwrap_or_else(|| "default".into());
            if cluster_admin_sas.contains(&(ns.clone(), sa.clone())) {
                findings.push(Finding {
                    severity: Severity::Critical,
                    rule_id: RuleId::SaClusterAdmin,
                    file: file_path.clone(),
                    resource: resource.clone(),
                    namespace: ns.clone(),
                    container: None,
                    message: format!(
                        "Workload runs as ServiceAccount '{sa}' with cluster-admin privileges"
                    ),
                });
            }
        }
    }

    Ok(findings)
}

fn scan_document(file_path: &str, doc: &Value) -> Vec<Finding> {
    if map_str(doc, &["kind"]).is_none() {
        return Vec::new();
    }
    let ns = namespace_of(doc);
    let mut findings = Vec::new();
    for (resource, spec) in iter_pod_specs(doc) {
        findings.extend(scan_pod_spec(file_path, &resource, &ns, spec));
    }
    findings
}

fn iter_pod_specs<'a>(doc: &'a Value) -> Vec<(String, &'a Value)> {
    let kind = map_str(doc, &["kind"]).unwrap_or_default();
    let mut out = Vec::new();
    if kind == "Pod" {
        if let Some(spec) = map_get(doc, &["spec"]) {
            out.push((resource_label(doc), spec));
        }
        return out;
    }
    if POD_TEMPLATE_KINDS.contains(&kind.as_str()) {
        // CronJob nests under spec.jobTemplate.spec.template.spec
        if kind == "CronJob" {
            if let Some(spec) = map_get(doc, &["spec", "jobTemplate", "spec", "template", "spec"]) {
                out.push((resource_label(doc), spec));
            }
            return out;
        }
        if let Some(spec) = map_get(doc, &["spec", "template", "spec"]) {
            out.push((resource_label(doc), spec));
        }
    }
    out
}

fn scan_pod_spec(file_path: &str, resource: &str, namespace: &str, spec: &Value) -> Vec<Finding> {
    let mut findings = Vec::new();

    if let Some(Value::Sequence(vols)) = map_get(spec, &["volumes"]) {
        for vol in vols {
            if map_get(vol, &["hostPath"]).is_some() {
                let vol_name = map_str(vol, &["name"]).unwrap_or_else(|| "<unnamed>".into());
                let path = map_str(vol, &["hostPath", "path"]).unwrap_or_default();
                findings.push(Finding {
                    severity: Severity::High,
                    rule_id: RuleId::HostPath,
                    file: file_path.into(),
                    resource: resource.into(),
                    namespace: namespace.into(),
                    container: None,
                    message: format!("Volume '{vol_name}' mounts hostPath: {path}"),
                });
            }
        }
    }

    let sa_name = map_str(spec, &["serviceAccountName"]);
    let automount = map_get(spec, &["automountServiceAccountToken"]).and_then(|v| v.as_bool());

    let uses_default = matches!(sa_name.as_deref(), None | Some("") | Some("default"));
    if uses_default {
        findings.push(Finding {
            severity: Severity::Low,
            rule_id: RuleId::SaDefault,
            file: file_path.into(),
            resource: resource.into(),
            namespace: namespace.into(),
            container: None,
            message: "Workload uses the default ServiceAccount".into(),
        });
    }

    if automount != Some(false) {
        let msg = if let Some(sa) = sa_name.as_deref().filter(|s| !s.is_empty()) {
            format!("automountServiceAccountToken not disabled for SA '{sa}'")
        } else {
            "Default SA token automount is enabled (set automountServiceAccountToken: false if unused)".into()
        };
        findings.push(Finding {
            severity: Severity::Medium,
            rule_id: RuleId::SaAutomount,
            file: file_path.into(),
            resource: resource.into(),
            namespace: namespace.into(),
            container: None,
            message: msg,
        });
    }

    for (key, label) in [
        ("containers", "Container"),
        ("initContainers", "Init container"),
        ("ephemeralContainers", "Ephemeral container"),
    ] {
        if let Some(Value::Sequence(containers)) = map_get(spec, &[key]) {
            for c in containers {
                findings.extend(scan_container(file_path, resource, namespace, c, label));
            }
        }
    }

    findings
}

fn scan_container(
    file_path: &str,
    resource: &str,
    namespace: &str,
    container: &Value,
    container_type: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let cname = map_str(container, &["name"]).unwrap_or_else(|| "<unnamed>".into());

    if map_get(container, &["securityContext", "privileged"]).and_then(|v| v.as_bool())
        == Some(true)
    {
        findings.push(Finding {
            severity: Severity::Critical,
            rule_id: RuleId::Privileged,
            file: file_path.into(),
            resource: resource.into(),
            namespace: namespace.into(),
            container: Some(cname.clone()),
            message: format!("{container_type} '{cname}' runs with privileged=true"),
        });
    }

    let image = map_str(container, &["image"]).unwrap_or_default();
    if is_latest_image(&image) {
        findings.push(Finding {
            severity: Severity::Medium,
            rule_id: RuleId::LatestTag,
            file: file_path.into(),
            resource: resource.into(),
            namespace: namespace.into(),
            container: Some(cname.clone()),
            message: format!(
                "{container_type} '{cname}' uses mutable tag: {}",
                if image.is_empty() { "<empty>" } else { &image }
            ),
        });
    }

    let has_limits = map_get(container, &["resources", "limits"])
        .map(|v| v.is_mapping() && !v.as_mapping().map(|m| m.is_empty()).unwrap_or(true))
        .unwrap_or(false);
    if !has_limits {
        findings.push(Finding {
            severity: Severity::Medium,
            rule_id: RuleId::NoLimits,
            file: file_path.into(),
            resource: resource.into(),
            namespace: namespace.into(),
            container: Some(cname.clone()),
            message: format!("{container_type} '{cname}' has no resources.limits"),
        });
    }

    findings
}

fn scan_bindings(
    file_path: &str,
    doc: &Value,
    cluster_admin_sas: &mut HashSet<(String, String)>,
) -> Vec<Finding> {
    let kind = map_str(doc, &["kind"]).unwrap_or_default();
    if kind != "RoleBinding" && kind != "ClusterRoleBinding" {
        return Vec::new();
    }
    let role_name = map_str(doc, &["roleRef", "name"]).unwrap_or_default();
    if !is_cluster_admin_ref(&role_name) {
        return Vec::new();
    }

    let mut findings = Vec::new();
    if let Some(Value::Sequence(subjects)) = map_get(doc, &["subjects"]) {
        for subject in subjects {
            if map_str(subject, &["kind"]).as_deref() != Some("ServiceAccount") {
                continue;
            }
            let name = match map_str(subject, &["name"]) {
                Some(n) if !n.is_empty() => n,
                _ => continue,
            };
            let ns = map_str(subject, &["namespace"]).unwrap_or_else(|| "default".into());
            cluster_admin_sas.insert((ns.clone(), name.clone()));
            findings.push(Finding {
                severity: Severity::Critical,
                rule_id: RuleId::SaClusterAdmin,
                file: file_path.into(),
                resource: resource_label(doc),
                namespace: ns,
                container: None,
                message: format!(
                    "ServiceAccount '{name}' bound to cluster-admin via {}",
                    resource_label(doc)
                ),
            });
        }
    }
    findings
}

fn is_cluster_admin_ref(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains("cluster-admin") || name == "*"
}

fn is_latest_image(image: &str) -> bool {
    let image = image.trim();
    if image.is_empty() {
        return false;
    }
    // Skip unresolved Jinja / Helm placeholders
    if image.contains("{{") || image.contains("${") || image == "__jinja__" {
        return false;
    }
    if image.contains('@') {
        return false;
    }
    match image.rsplit_once(':') {
        None => true,
        Some((_, tag)) => tag.eq_ignore_ascii_case("latest"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jinja_nginx_template_parses() {
        let path = Path::new(r"C:\Users\marci\small-homelab-boi\ansible\roles\demo_app\templates\nginx.yaml.j2");
        if !path.exists() {
            return;
        }
        let findings = scan_file(path).unwrap();
        assert!(
            findings.iter().any(|f| f.resource.contains("nginx-demo")),
            "expected findings on nginx-demo, got {findings:?}"
        );
    }

    #[test]
    fn neutralize_preserves_utf8() {
        let raw = "apiVersion: v1\nkind: Pod\nmetadata:\n  name: {{ x }}\n  note: It works — yes\n";
        let out = neutralize_jinja_values(raw);
        assert!(out.contains("It works — yes"));
        assert!(out.contains("\"__jinja__\""));
    }
}

fn resource_label(doc: &Value) -> String {
    let kind = map_str(doc, &["kind"]).unwrap_or_else(|| "Unknown".into());
    let name = map_str(doc, &["metadata", "name"]).unwrap_or_else(|| "<unnamed>".into());
    format!("{kind}/{name}")
}

fn namespace_of(doc: &Value) -> String {
    map_str(doc, &["metadata", "namespace"]).unwrap_or_else(|| "default".into())
}

fn map_get<'a>(v: &'a Value, keys: &[&str]) -> Option<&'a Value> {
    let mut cur = v;
    for key in keys {
        cur = cur.as_mapping()?.get(Value::String((*key).into()))?;
    }
    Some(cur)
}

fn map_str(v: &Value, keys: &[&str]) -> Option<String> {
    map_get(v, keys).and_then(|x| match x {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    })
}
