mod export;
mod models;
mod scanner;
mod tui;

use crate::export::{
    build_report, exit_code, write_json, write_report_to_path, write_sarif, write_text, OutputFormat,
};
use crate::models::Severity;
use anyhow::{bail, Result};
use clap::{Parser, ValueEnum};
use std::io::{self, IsTerminal};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum FormatArg {
    Text,
    Json,
    Sarif,
}

impl From<FormatArg> for OutputFormat {
    fn from(v: FormatArg) -> Self {
        match v {
            FormatArg::Text => OutputFormat::Text,
            FormatArg::Json => OutputFormat::Json,
            FormatArg::Sarif => OutputFormat::Sarif,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum FailOnArg {
    Critical,
    High,
    Medium,
    Low,
    Never,
}

impl FailOnArg {
    fn to_threshold(self) -> Option<Severity> {
        match self {
            Self::Critical => Some(Severity::Critical),
            Self::High => Some(Severity::High),
            Self::Medium => Some(Severity::Medium),
            Self::Low => Some(Severity::Low),
            Self::Never => None,
        }
    }
}

/// Kubernetes manifest security scanner (TUI + CI-friendly CLI).
#[derive(Parser, Debug)]
#[command(name = "k8s-sec", version, about)]
struct Cli {
    /// File or directory with YAML manifests
    #[arg(default_value = ".")]
    path: PathBuf,

    /// Force text/JSON/SARIF output (no TUI)
    #[arg(long)]
    cli: bool,

    /// Force interactive TUI
    #[arg(long)]
    tui: bool,

    /// Output format (implies --cli)
    #[arg(long, value_enum, default_value_t = FormatArg::Text)]
    format: FormatArg,

    /// Write report to this file (format still applies)
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Fail (exit 1) if any finding is at or above this severity [default: high]
    #[arg(long, value_enum, default_value_t = FailOnArg::High)]
    fail_on: FailOnArg,
}

fn main() -> ExitCode {
    match real_main() {
        Ok(code) => ExitCode::from(code as u8),
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn real_main() -> Result<i32> {
    let cli = Cli::parse();
    if !cli.path.exists() {
        bail!("path not found: {}", cli.path.display());
    }
    let target = strip_unc_prefix(cli.path.canonicalize().unwrap_or(cli.path.clone()));

    let want_tui = cli.tui
        || (!cli.cli
            && cli.output.is_none()
            && matches!(cli.format, FormatArg::Text)
            && io::stdout().is_terminal());

    if want_tui {
        tui::run(&target)?;
        return Ok(0);
    }

    let findings = scanner::scan_path(&target)?;
    let report = build_report(&target, findings);
    let format = OutputFormat::from(cli.format);

    if let Some(path) = &cli.output {
        write_report_to_path(&report, format, path)?;
        eprintln!("wrote {} ({format:?})", path.display());
    } else {
        let stdout = io::stdout();
        let mut out = stdout.lock();
        match format {
            OutputFormat::Text => write_text(&report, &mut out)?,
            OutputFormat::Json => write_json(&report, &mut out)?,
            OutputFormat::Sarif => write_sarif(&report, &mut out)?,
        }
    }

    Ok(exit_code(&report.findings, cli.fail_on.to_threshold()))
}

fn strip_unc_prefix(path: PathBuf) -> PathBuf {
    let s = path.to_string_lossy();
    PathBuf::from(s.strip_prefix(r"\\?\").unwrap_or(&s))
}
