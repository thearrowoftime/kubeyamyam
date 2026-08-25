# kubeyamyam

Kubernetes security scanner with JSON export.

Static analysis only — reads YAML from disk (no live cluster access). Checks privileged containers, `hostPath` mounts, `:latest` tags, missing resource limits, and ServiceAccount misuse (including `cluster-admin` bindings).

## Install

```bash
cargo install --path .
# or
cargo build --release
```

## Usage

```bash
# TUI (default on a TTY)
kubeyamyam examples

# CLI
kubeyamyam --cli examples
kubeyamyam --format json examples
kubeyamyam --format sarif --output findings.sarif --fail-on high examples
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Scan OK — no findings at/above `--fail-on` |
| `1` | Findings at/above `--fail-on` (default: `high`) |
| `2` | Usage / I/O error |

`--fail-on never` always exits `0` after a successful scan.

### Rules

| ID | Severity | Check |
|----|----------|-------|
| `K8S-PRIV` | CRITICAL | `privileged: true` |
| `K8S-HOSTPATH` | HIGH | `hostPath` volumes |
| `K8S-LATEST` | MEDIUM | `:latest` / untagged images |
| `K8S-LIMITS` | MEDIUM | missing `resources.limits` |
| `K8S-SA-DEFAULT` | LOW | default ServiceAccount |
| `K8S-SA-AUTOMOUNT` | MEDIUM | SA token automount enabled |
| `K8S-SA-CLUSTERADMIN` | CRITICAL | SA bound to `cluster-admin` |

Supports `Pod`, `Deployment`, `StatefulSet`, `DaemonSet`, `Job`, `CronJob`,
`ReplicaSet`, plus `RoleBinding` / `ClusterRoleBinding`. Ansible/Helm Jinja
placeholders in `*.yaml.j2` are neutralized so templates still parse.

### TUI keys

| Key | Action |
|-----|--------|
| `Enter` / `F5` | Scan |
| `/` | Edit path |
| `f` / `r` | Filter severity / rule |
| `j`/`k` | Navigate |
| `?` | Help |
| `q` | Quit |

## Homelab suite

Part of the same sibling layout as the rest of the k3s homelab tooling:

```text
~/Projects/
  small-homelab-boi/   # Ansible + k3s lab (provisioning)
  notears/             # chaos + Prometheus/Alertmanager detection
  sneaky-boi/          # secret scanner (.env, compose, ansible, k8s, HA)
  kubeyamyam/          # this repo — workload misconfig scanner
```

| Repo | Role vs kubeyamyam |
|------|--------------------|
| [small-homelab-boi](https://github.com/thearrowoftime/small-homelab-boi) | Target lab — scan its Ansible K8s templates / manifests before deploy |
| [notears](https://github.com/thearrowoftime/notears) | Runtime chaos + alert validation (pairs with SHB; complementary to static scans) |
| [sneaky-boi](https://github.com/thearrowoftime/sneaky-boi) | Finds leaked credentials; kubeyamyam finds insecure workload *config* |

Suggested flow against the lab:

```bash
# secrets in diffs
sneaky-boi ../small-homelab-boi --only env,compose,ansible,k8s

# workload hardening
kubeyamyam --cli --fail-on high ../small-homelab-boi

# chaos + detection
notears -c ../notears/config.yaml doctor
```
