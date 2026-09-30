#!/usr/bin/env python3
"""Refuse a release whose shipped source has not been through the OIDF conformance suite.

What belongs here: the CHECK only. Running the suite needs a local Docker stack and key material that
deliberately never enters this repository, so CI cannot run it and must instead verify that someone did.

Why a check and not a reminder. The runbook used to make this step conditional on whether a change
"touched OpenID4VP behaviour", which asks the releaser to judge. That judgment is unreliable in both
directions, because the blast radius of a change is not visible from its subject line. A package name
does not bound what the conformance modules exercise: every positive module depends on the issuer's
certificate resolving to a trusted anchor, so a change filed under trust is on the tested path. Nor
does "dependency bumps only", since a transitive JWT or CBOR library sits directly under the
verification code. A question nobody is forced to answer gets answered by whoever is in a hurry, so
this asks nobody and checks instead.

WHAT IT COMPARES, and why that is the right thing. Not the commit: a version bump and this record
itself are commits that change nothing a wallet can observe, and gating on the commit would demand a
re-run that tests identical bytes. It compares the git TREE OBJECT of `src/`, which is the id of the
shipped source's exact content. Equal tree means the suite ran against these bytes. Different tree means
it did not, whatever the commit graph looks like in between.

DEPENDENCIES ARE INSIDE THAT TREE, as the resolved graph. Every project under `src/` commits a lock
file, `packages.lock.json`, beside its `.csproj`, so the tree covers the package versions each project
resolves, transitive ones included. CI, release and the harness build restore in locked mode, so a
dependency change that did not regenerate the lock files fails there, and regenerating them moves the
tree, which this gate then refuses until both plans are re-run. `lock_files_missing` refuses a release
where a `src/` project commits no lock file, or commits it as a symlink, whose target the tree does
not hold.

WHAT IT DOES NOT COVER, stated because the gate would otherwise read as a stronger promise than it is:
the suite's own version (the harness pulls the `latest` image, so a passing record may have been made
against an earlier suite), the harness configuration, and anything outside `src/` that can still reach
behaviour, such as the SDK pin in `global.json` or a source file that a build file outside `src/` adds to
the compile. Lock files pin packages, not source. Like the rest of this gate it guards against
accidents, not deliberate edits: a build file outside `src/` can still move the lock file elsewhere
(`NuGetLockFilePath`), or change a dependency's metadata, such as `PrivateAssets`, which alters the
packed dependency list without changing resolution. It answers one question only: has this exact
shipped source passed both plans.
"""

import json
import pathlib
import subprocess
import sys

# Both formats, because HAIP certifies them separately and a verifier that passes one can fail the
# other: they share almost no verification code below the request. The key is the plan's
# `credential_format` variant, which is what the suite itself calls them.
REQUIRED_VARIANTS = ("sd_jwt_vc", "iso_mdl")

RECORD_PATH = "conformance-record.json"

# NuGet writes it beside the project file when RestorePackagesWithLockFile is on.
LOCK_FILE = "packages.lock.json"


def repo_root():
    return pathlib.Path(
        subprocess.run(["git", "rev-parse", "--show-toplevel"],
                       capture_output=True, text=True, check=True).stdout.strip())


def src_tree(root):
    """The git object id of the src/ tree, which changes if and only if shipped source content does."""
    return subprocess.run(["git", "rev-parse", "HEAD:src"],
                          cwd=root, capture_output=True, text=True, check=True).stdout.strip()


def lock_files_missing(root):
    """Every src/ project whose lock file HEAD does not carry as a regular file. HEAD, like HEAD:src, so
    both halves judge the same commit."""
    # One line per file: "<mode> <type> <object>\t<path>". Mode 120000 is a symlink.
    entries = subprocess.run(["git", "ls-tree", "-r", "HEAD", "src"],
                             cwd=root, capture_output=True, text=True, check=True).stdout.splitlines()
    modes = {line.split("\t", 1)[1]: line.split(" ", 1)[0] for line in entries}
    projects = [p for p in modes if p.endswith(".csproj")]
    if not projects:
        sys.exit("HEAD has no project under src/, so there is nothing this gate can vouch for.")
    missing = []
    for project in projects:
        lock = str(pathlib.PurePosixPath(project).parent / LOCK_FILE)
        if lock not in modes:
            missing.append(project)
        elif modes[lock] == "120000":
            missing.append(f"{project} (its {LOCK_FILE} is a symlink)")
    return missing


def main():
    root = repo_root()

    unlocked = lock_files_missing(root)
    if unlocked:
        print(f"These src/ projects commit no regular {LOCK_FILE}, so their packages are not pinned by the src tree:")
        for project in unlocked:
            print(f"  {project}")
        sys.exit("Set RestorePackagesWithLockFile in each, run dotnet restore, and commit the lock files.")
    record_file = root / RECORD_PATH

    if not record_file.exists():
        sys.exit(f"{RECORD_PATH} is missing. No release may publish source the conformance suite has "
                 f"not seen. See RELEASING.md step 2.")

    runs = json.loads(record_file.read_text()).get("runs", {})
    expected = src_tree(root)

    problems = []
    for variant in REQUIRED_VARIANTS:
        run = runs.get(variant)
        if run is None:
            problems.append(f"{variant}: no run recorded")
        elif run.get("srcTree") != expected:
            problems.append(
                f"{variant}: recorded against src tree {run.get('srcTree', '(absent)')[:12]} "
                f"from {run.get('commit', '(absent)')[:12]}, but this release ships {expected[:12]}")

    if problems:
        print(f"Shipped source is src tree {expected[:12]}, and the conformance record does not cover it:")
        for problem in problems:
            print(f"  {problem}")
        sys.exit("Re-run both plans and commit the record. See RELEASING.md step 2.")

    print(f"Conformance record covers src tree {expected[:12]}: "
          + ", ".join(f"{v} plan {runs[v].get('planId', '?')}" for v in REQUIRED_VARIANTS))


if __name__ == "__main__":
    main()
