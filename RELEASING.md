# Releasing Tessio.Verifier

The packages are consumed by a consuming application (Tessio.Cloud) and by Tessio.Labs, both via
`PackageReference`. A library fix does not reach either until it is published and the consumer's
version is bumped. Keep those two steps together: the gap between them is how two `client_metadata`
builders once drifted for weeks until an external conformance suite caught production advertising
values HAIP rejects.

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

- **a consuming application**: `the consuming project/Tessio.Verification.csproj`, the
  `Tessio.Verifier.AspNetCore` `Version`. Because the product calls the library's own types (for
  example `Tessio.Verifier.OpenId4Vp.ClientMetadata`), an **API** change surfaces at compile time
  against a stale package, which is the structural guard. A behaviour-only fix (same API) does not, so
  the bump is the discipline that carries it.
- **A second consumer**: its own project file, if it consumes the changed package.

## Co-developing before a release

You do not have to publish to test a consumer against an unreleased change. In a consuming application:

```sh
export TessioVerifierSource=/path/to/tessio-verifier
dotnet build      # references the verifier source projects, not the package
```

Unset the env var to return to the published package. CI and production always use the package, because
the env var is never set there.
