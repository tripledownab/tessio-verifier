## What and why

<!-- One or two sentences. Link the issue if there is one. -->

## Checklist

- [ ] Tests cover the change, including negative cases where applicable
- [ ] `dotnet build` and `dotnet test` pass locally (warnings are errors)
- [ ] Spec-relevant code carries a `// SPEC:` citation
- [ ] Docs touched if behavior or API changed (README, docs/, XML docs)

## Frozen contracts (`contracts-v0`)

<!-- Tick exactly one. Leaving all three unticked reads as unreviewed, which is worse than either
     true answer. What may be ADDED depends on the kind: a record or DTO takes a new optional
     init-only property, an interface and an enum take nothing. See CONTRIBUTING.md. -->

- [ ] Not modified
- [ ] Modified in a permitted additive way. Name the type, its kind and the member added: <!-- e.g. IssuerInfo, record, optional init-only string? TrustListSource -->
- [ ] Modified in a breaking way. Issue link: <!-- required; open the issue before sending the PR -->
