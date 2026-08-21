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

1. `dotnet build && dotnet test` green, 0 warnings.
2. If the change touched OpenID4VP behaviour, re-run the affected OIDF conformance modules against the
   local suite (`tools/conformance-harness/README.md`). The SD-JWT VC HAIP plan passing is the bar for
   a verifier release.
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
