# kubeyamyam

Kubernetes manifest security scanner (TUI, JSON, SARIF). Static YAML only — no live cluster. Required: Rust.

```bash
cargo install --path .
kubeyamyam examples
kubeyamyam --cli --format json examples
kubeyamyam --format sarif --output findings.sarif --fail-on high examples
```

Homelab siblings: [small-homelab-boi](https://github.com/thearrowoftime/small-homelab-boi), [notears](https://github.com/thearrowoftime/notears), [sneaky-boi](https://github.com/thearrowoftime/sneaky-boi).
