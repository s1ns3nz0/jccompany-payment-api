# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly.

**Contact:** security@miata.cloud

**Do NOT:**
- Open a public GitHub Issue for security vulnerabilities
- Disclose the vulnerability publicly before a fix is available

## Response Timeline

| Severity | Acknowledgment | Fix Target |
|----------|---------------|------------|
| Critical | 24 hours | 3 days |
| High | 48 hours | 7 days |
| Medium | 72 hours | 30 days |
| Low | 1 week | 90 days |

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x (latest) | Yes |

## Security Controls

This project implements automated security scanning via CI/CD pipeline:

- **SAST:** Semgrep, SpotBugs/FindSecBugs
- **DAST:** OWASP ZAP
- **SCA:** Grype, Trivy (NVD + GHSA + Alpine Secdb)
- **Secret Detection:** Gitleaks
- **IaC Scanning:** Checkov (Kubernetes + Dockerfile)
- **Container Security:** Trivy CIS Docker Benchmark, kube-bench CIS K8s
- **Supply Chain:** Cosign OIDC signing, SLSA provenance, CycloneDX SBOM
- **Risk Assessment:** AI-powered 6-phase assessment (SP 800-30)

All dependencies are SHA-pinned and SHA256-verified per SP 800-204D.
