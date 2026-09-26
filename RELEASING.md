# Releasing Tessio.Verifier

Downstream applications consume these packages via `PackageReference`. A library fix does not reach any
of them until it is published and the consumer's version is bumped. Keep those two steps together: the
gap between them is how two `client_metadata` builders once drifted for weeks, until an external
conformance suite caught a deployed consumer advertising values HAIP rejects.

## Publishing is tag-driven, not manual

`.github/workflows/release.yml` does the whole publish on a `v*` tag: restore, build, test, pack,
push to nuget.org via **Trusted Publishing** (OIDC exchanges for a one-hour key, so there is no
long-lived secret to leak), and create the GitHub Release. Do **not** `dotnet nuget push` by hand; that
bypasses the tests, the OIDC path, and the Release note, and it is how the repo's Releases page fell
four versions behind nuget.org once already.

## The version is the single source of truth

`Directory.Build.props` `<Version>` is the version, and the tag must match it (`<Version>0.4.0</Version>`
→ tag `v0.4.0`). Bump it in the same commit as any change to shipped behaviour or public API. Patch for
a fix, minor for additive API. A `contracts-v0` change must be additive (see the frozen-contracts note).

## Steps

1. `dotnet build && dotnet test` green, 0 warnings. Run it as `dotnet test Tessio.Verifier.sln` and
   **count the results**: a bare `dotnet test` at the repo root has reported only two of the five test
   projects, which reads as a clean pass and is a partial one.

   Count occurrences, not lines. The runs finish in parallel and two results land on one physical line
   often enough to matter, so `grep -c` undercounts a fully green run and sends you looking for a
   project that did in fact report. Expect one result per test project per target framework:

   ```sh
   out=$(dotnet test Tessio.Verifier.sln 2>&1)
   printf '%s' "$out" | grep -o 'Passed!' | wc -l   # expect 2 x the number of test projects
   printf '%s' "$out" | grep -o 'Failed!' | wc -l   # expect 0
   ```

   **Then run CI on Windows, before you tag.** `release.yml` is Ubuntu-only, and `ci.yml` only adds
   Windows on `schedule` or `workflow_dispatch`, so a tag can publish a defect no release run could
   ever see. Fire it by hand and wait for both legs:

   ```sh
   gh workflow run ci.yml --ref <your-branch>
   gh run view <run-id> --json jobs -q '.jobs[] | "\(.name): \(.conclusion)"'
   ```

   This is not precautionary. 0.8.0 shipped a Windows-only defect this way, and 0.10.0 would have: a
   certificate whose subjectAltName URI matched `iss` exactly was accepted on Unix and refused on
   Windows, because the check read the platform's RENDERING of the extension rather than its DER. The
   Ubuntu leg passed both times. Anything touching `System.Security.Cryptography.X509Certificates`,
   path handling or text formatting deserves it most, but it costs one run, so just do it.
2. Run **both** OIDF conformance plans against the local suite and commit the record
   (`tools/conformance-harness/README.md` has the setup):

   ```sh
   cd tools/conformance-harness
   python3 run-plan.py --clone-plan <sd_jwt_vc plan> --harness https://localhost:5100 \
     --record ../../conformance-record.json
   # kill the harness, swap appsettings.Local.json to the other variant, start it again
   python3 run-plan.py --clone-plan <iso_mdl plan> --harness https://localhost:5100 \
     --record ../../conformance-record.json
   ```

   `--record` writes only after the run passes, and refuses a dirty `src/`, so the record cannot
   describe bytes the suite did not see. `release.yml` compares the recorded src tree against the
   tag's and refuses to publish when they differ, which makes a skipped run a build failure rather
   than an oversight.

   **There is deliberately no "only if the change touched OpenID4VP behaviour" here.** This step used
   to carry that conditional, and it asks the releaser to judge a blast radius that is not visible
   from a change's subject line. A package name does not bound what the modules exercise: every
   positive module depends on the issuer's certificate resolving to a trusted anchor, so a change
   filed under trust is on the tested path. Neither does "dependency bumps only", because a JWT or
   CBOR library sits directly under the verification code. Run both plans, every time.
3. Bump `<Version>` in `Directory.Build.props`, commit, push `main`.
4. Tag and push:

   ```sh
   git tag v0.4.0
   git push origin v0.4.0
   ```

   The `release` workflow publishes and cuts the GitHub Release. Confirm it went green before relying
   on the package (a tag whose run has not finished has published nothing).
5. **Bump the consumers in the same session.** This is the step that prevents drift.

## Bumping the consumers

In each consuming project, raise the `Version` on the `PackageReference` for every package that changed.

A consumer that calls the library's own types (for example `Tessio.Verifier.OpenId4Vp.ClientMetadata`)
gets one structural guard for free: an **API** change fails to compile against a stale package. A
behaviour-only fix keeps the same API and compiles fine, so nothing catches it. The bump is the only
discipline that carries that case, which is why it belongs in the same session as the release.

## Co-developing before a release

You do not have to publish to test a consumer against an unreleased change. Point an environment
variable at a local checkout of this repository:

```sh
export TessioVerifierSource=/path/to/tessio-verifier
dotnet build      # references the verifier source projects, not the package
```

This requires the consumer's build to honour the variable, by swapping its `PackageReference` for a
`ProjectReference` when it is set. Unset it to return to the published package. Keep it unset in CI and
in production, so what ships is always the released package.
