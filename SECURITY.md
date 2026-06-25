# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in nono-py, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please [open a GitHub Security Advisory](https://github.com/nolabs-ai/nono-py/security/advisories/new) with:

- A description of the vulnerability
- Steps to reproduce the issue
- Affected versions
- Any potential impact assessment

We will acknowledge your report within 48 hours and work with you to understand and address the issue.

## Security Model

nono-py provides OS-enforced sandboxing through:

- **Landlock** (Linux kernel 5.13+) for filesystem and network restrictions
- **Seatbelt** (macOS) for application sandboxing

The security boundary is enforced at the kernel level. The Python bindings expose configuration and setup; actual enforcement happens in Rust and the OS kernel.

### Key Security Properties

- **Irreversible sandbox**: once `apply()` is called, permissions cannot be expanded
- **Credential isolation**: real API keys never reach sandboxed processes (proxy handles injection)
- **Cloud metadata protection**: `169.254.169.254` and equivalents are always blocked
- **DNS rebinding protection**: resolved IPs are validated against link-local ranges
- **Audit logging**: all proxy requests are logged with sensitive data excluded

## Disclosure Policy

- We follow responsible disclosure practices
- Security fixes will be released as patch versions
- CVEs will be requested for significant vulnerabilities
- A security advisory will be published on GitHub once a fix is available
