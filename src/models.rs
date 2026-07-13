use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "CRITICAL",
            Self::High => "HIGH",
            Self::Medium => "MEDIUM",
            Self::Low => "LOW",
        }
    }

    pub fn rank(self) -> u8 {
        match self {
            Self::Critical => 0,
            Self::High => 1,
            Self::Medium => 2,
            Self::Low => 3,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RuleId {
    #[serde(rename = "K8S-PRIV")]
    Privileged,
    #[serde(rename = "K8S-HOSTPATH")]
    HostPath,
    #[serde(rename = "K8S-LATEST")]
    LatestTag,
    #[serde(rename = "K8S-LIMITS")]
    NoLimits,
    #[serde(rename = "K8S-SA-DEFAULT")]
    SaDefault,
    #[serde(rename = "K8S-SA-AUTOMOUNT")]
    SaAutomount,
    #[serde(rename = "K8S-SA-CLUSTERADMIN")]
    SaClusterAdmin,
}

impl RuleId {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Privileged => "K8S-PRIV",
            Self::HostPath => "K8S-HOSTPATH",
            Self::LatestTag => "K8S-LATEST",
            Self::NoLimits => "K8S-LIMITS",
            Self::SaDefault => "K8S-SA-DEFAULT",
            Self::SaAutomount => "K8S-SA-AUTOMOUNT",
            Self::SaClusterAdmin => "K8S-SA-CLUSTERADMIN",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Privileged => "Privileged container",
            Self::HostPath => "hostPath volume",
            Self::LatestTag => "Latest image tag",
            Self::NoLimits => "Missing resource limits",
            Self::SaDefault => "Default ServiceAccount",
            Self::SaAutomount => "SA token automount",
            Self::SaClusterAdmin => "Cluster-admin binding",
        }
    }

    pub fn help_uri(self) -> &'static str {
        match self {
            Self::Privileged => {
                "https://kubernetes.io/docs/concepts/security/pod-security-standards/"
            }
            Self::HostPath => {
                "https://kubernetes.io/docs/concepts/storage/volumes/#hostpath"
            }
            Self::LatestTag => {
                "https://kubernetes.io/docs/concepts/containers/images/#updating-images"
            }
            Self::NoLimits => {
                "https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/"
            }
            Self::SaDefault | Self::SaAutomount | Self::SaClusterAdmin => {
                "https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/"
            }
        }
    }

    pub fn all() -> &'static [RuleId] {
        &[
            Self::Privileged,
            Self::HostPath,
            Self::LatestTag,
            Self::NoLimits,
            Self::SaDefault,
            Self::SaAutomount,
            Self::SaClusterAdmin,
        ]
    }
}

impl fmt::Display for RuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub severity: Severity,
    pub rule_id: RuleId,
    pub file: String,
    pub resource: String,
    pub namespace: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub tool: String,
    pub version: String,
    pub path: String,
    pub findings: Vec<Finding>,
    pub summary: ScanSummary,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanSummary {
    pub total: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
}

impl ScanSummary {
    pub fn from_findings(findings: &[Finding]) -> Self {
        let mut s = Self {
            total: findings.len(),
            ..Default::default()
        };
        for f in findings {
            match f.severity {
                Severity::Critical => s.critical += 1,
                Severity::High => s.high += 1,
                Severity::Medium => s.medium += 1,
                Severity::Low => s.low += 1,
            }
        }
        s
    }
}
