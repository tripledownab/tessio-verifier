# Releasing Tessio.Verifier

Downstream applications consume these packages via `PackageReference`. A library fix does not reach any
of them until it is published and the consumer's version is bumped. Keep those two steps together: while
they are apart, a consumer runs code the library has already fixed, and nothing fails to say so.

## Publishing is tag-driven, not manual

`.github/workflows/release.yml` does the whole publish on a `v*` tag: restore, build, test, pack,
push to nuget.org via **Trusted Publishing** (OIDC exchanges for a one-hour key, so there is no
long-lived secret to leak), and create the GitHub Release. Do **not** `dotnet nuget push` by hand; that
bypasses the tests, the OIDC path, and the Release note, and leaves the repo's Releases page behind
nuget.org, which reads as an abandoned project to anyone evaluating the library.

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

   This is not precautionary. Platforms render the same certificate differently, so a check that reads
   the platform's RENDERING of an extension rather than its DER can accept a certificate on Unix and
   refuse it on Windows, and the Ubuntu leg passes either way. Anything touching
   `System.Security.Cryptography.X509Certificates`, path handling or text formatting deserves it most,
   but it costs one run, so just do it.
2. Run **both** OIDF conformance plans against the local suite and commit the record
   (`tools/conformance-harness/README.md` has the setup):

   ```sh
   cd tools/conformance-harness
   # A recording needs a harness built from a clean export of HEAD, not from the working tree:
   sh serve-export.sh <your keys>/appsettings.Local.oidf-sdjwt.json &   # wait until /config answers
   python3 run-plan.py --clone-plan <sd_jwt_vc plan> --harness https://localhost:5100 \
     --record ../../conformance-record.json

   # Between variants. Stop only what holds THIS port: other harnesses may be running on others.
   # The loop escalates because a process can ignore the first signal, and it feeds the pids through
   # xargs because zsh does not split an unquoted $pids, so two processes on one port would spin a
   # `kill -9 $pids` loop forever. Two processes on one port is exactly the stale-harness case.
   lsof -nP -iTCP:5100 -sTCP:LISTEN -t | xargs kill 2>/dev/null
   while pids=$(lsof -nP -iTCP:5100 -sTCP:LISTEN -t); do echo "$pids" | xargs kill -9; sleep 1; done

   sh serve-export.sh <your keys>/appsettings.Local.oidf-mdoc.json &
   python3 run-plan.py --clone-plan <iso_mdl plan> --harness https://localhost:5100 \
     --record ../../conformance-record.json
   ```

   `--record` writes only after the run passes, and only against a harness `serve-export.sh` built
   from an export of `HEAD` it verified file by file and compiled isolated from the machine, so the
   source that ran is `HEAD:src`. A harness built from the working tree is refused for a recording,
   because the compiler can read bytes git does not describe there: the harness README lists them. `release.yml` compares the recorded src tree against the
   tag's and refuses to publish when they differ, which makes a skipped run a build failure rather
   than an oversight.

   **If you get the sequence wrong, the script stops before it creates anything.** It reads the
   RUNNING harness's settings from `/config` and compares them with the plan, and the `src/` tree the
   harness ran with `HEAD:src` for a recording, or with the tree on disk for a regression run. A stale harness is caught by name,
   whether it is the other variant or the same variant built before your last change, in another
   checkout, or from edits since reverted through git. `tools/conformance-harness/README.md` lists every check.
   Nothing is recorded on a crash, because `--record` runs last.

   **There is deliberately no "only if the change touched OpenID4VP behaviour" here.** This step used
   to carry that conditional, and it asks the releaser to judge a blast radius that is not visible
   from a change's subject line. A package name does not bound what the modules exercise: every
   positive module depends on the issuer's certificate resolving to a trusted anchor, so a change
   filed under trust is on the tested path. Neither does "dependency bumps only", because a JWT or
   CBOR library sits directly under the verification code. Run both plans, every time.

   A dependency bump is inside what the gate compares. Each `src/` project commits its
   `packages.lock.json`, so a bump moves the `src` tree, and release restores in locked mode, so a
   bump that did not regenerate the lock files fails. This guards against accidents, not deliberate
   edits to the build files; `tools/check-conformance-record.py` lists what it does not cover.
3. Bump `<Version>` in `Directory.Build.props`, commit, push `main`.
4. Tag and push:

   ```sh
   git tag v0.4.0
   git push origin v0.4.0
   ```

   The `release` workflow publishes and cuts the GitHub Release. Confirm it went green before relying
   on the package (a tag whose run has not finished has published nothing).
5. **Write any observable behaviour change into the Release by hand.** `gh release create` runs with
   `--generate-notes` and nothing else, so the note it produces is the list of merged pull request
   titles since the last tag. A title says what a change was for; it does not say what a consumer has
   to do differently, and a consumer reading only the Release will not open the pull requests.

   So read the merged titles, open any that changed behaviour, and append an **Upgrading** section:

   ```sh
   gh release view v0.13.0 --json body -q .body > /tmp/notes.md
   # add the Upgrading section at the top of /tmp/notes.md, then:
   gh release edit v0.13.0 --notes-file /tmp/notes.md
   ```

   What counts: a changed default, a value a consumer parses that now reads differently, a new
   required configuration step, a removed or renamed public member. 0.13.0 is the example that made
   this a step. The session status endpoint and its SSE stream now replace every
   `VerificationError.Message` with a fixed sentence, so a consumer that logged or displayed those
   messages finds them all identical from 0.13.0 on. `Code` is unchanged and is what to read instead.
   Nothing about that is guessable from the pull request title.
6. **Bump the consumers in the same session.** This is the step that prevents drift.

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
