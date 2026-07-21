# Security policy

Tessio.Verifier is a credential verifier. Bugs in it can have security consequences for relying
parties, so we take reports seriously.

## Reporting a vulnerability

Please report vulnerabilities privately through
[GitHub security advisories](https://github.com/tripledownab/tessio-verifier/security/advisories/new).
Do not open a public issue for anything you believe is exploitable.

Include what you can: affected package and version, a description of the issue, and ideally a
reproduction (a crafted credential or presentation is the most useful form).

We aim to acknowledge reports within 3 business days.

## Scope

In scope:

- Verification bypasses: forged or tampered credentials accepted, disclosure or key binding
  checks skipped, trust decisions bypassed
- Replay: reuse of nonces, states, or presentations
- Parsing vulnerabilities in SD-JWT, JAR, or wallet response handling

Out of scope:

- Vulnerabilities in the demo and mock modes when used as documented (they are development tools)
- Issues requiring a compromised host or trust list configuration

## Supported versions

Fixes land on the latest released 0.x version. There are no backports during 0.x.
