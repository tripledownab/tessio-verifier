#!/bin/sh
# Starts the harness for a RECORDING run, built from a verified export of HEAD rather than from the
# working tree. Everything about how a recorded harness is built belongs here.
#
# Usage: sh serve-export.sh <appsettings.Local.json for the variant>
#
# Why an export. The working tree can compile bytes git does not describe: a gitignored file under src/,
# a revert that keeps an old timestamp so the incremental build skips the recompile, a file saved during
# the build, a build file imported from a directory above the checkout, line endings converted on the
# way in. So this exports HEAD into a fresh directory, VERIFIES every exported file against HEAD's blob
# byte for byte, and builds it with the ways MSBuild reaches outside a project turned off.
#
# The build is told the commit it exported, and the harness reports it on /config as exportOf, so
# run-plan.py --record can check what ran against HEAD:src.
#
# What this defends against is a working copy or a machine in an accidental state. It does not stop
# someone who means to forge a record, who could edit this script as easily.
set -eu

if [ $# -ne 1 ] || [ ! -f "$1" ]; then
    echo "usage: sh serve-export.sh <appsettings.Local.json for the variant>" >&2
    exit 2
fi
settings=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")

here=$(cd "$(dirname "$0")" && pwd)
root=$(git -C "$here" rev-parse --show-toplevel)
commit=$(git -C "$root" rev-parse HEAD)

# A fresh directory nobody else can write above. MSBuild and NuGet read files from every directory
# ABOVE a project, and NuGet.Config can add a package source, so a group- or world-writable ancestor
# such as /tmp would let another account change what this build imports or restores. macOS gives each
# user a private TMPDIR; Linux usually sets none, so fall back to the user's cache rather than to /tmp.
# Then check, rather than assume, every ancestor of the PHYSICAL path: a symlinked ancestor reports the
# link's own permissions, so on macOS /tmp would pass while /private/tmp is world-writable.
base=${TMPDIR:-$HOME/.cache}
mkdir -p "$base"
work=$(mktemp -d "$base/harness-export.XXXXXX")
work=$(cd "$work" && pwd -P)

pid=
cleanup() {
    # A second Ctrl-C or kill during cleanup would otherwise run `exit` again and leave before rm -rf.
    trap '' INT TERM HUP
    if [ -n "$pid" ]; then
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    fi
    rm -rf "$work"
}
# Every way out removes the export and stops the harness with it. Signals exit through the EXIT trap,
# so a Ctrl-C, a terminated shell and a harness stopped by the port loop in RELEASING.md all end in
# cleanup; a harness left listening would answer the next run with this build. One exception: started
# from a non-interactive script with &, the shell inherits SIGINT as ignored and POSIX forbids trapping
# it, so stop it with SIGTERM or the port loop, which both clean up.
trap cleanup EXIT
# Each handler's FIRST act is to ignore further signals. Ignoring them in cleanup() came too late: a
# second kill arriving between the first handler's exit and the EXIT trap ran exit again, and the shell
# left without cleaning up, orphaning the harness on the port. Signals of one kind do not queue, so two
# arriving before the handler starts are delivered once.
trap 'trap "" INT TERM HUP; exit 130' INT
trap 'trap "" INT TERM HUP; exit 143' TERM HUP

dir=$(dirname "$work")
while :; do
    # World- or group-writable anywhere is refused, owner or not: on macOS every account's primary group
    # is staff, so a directory of ours writable by its group is writable by every other account.
    # find -perm -MODE needs ALL of MODE's bits, so each bit is its own test.
    if [ -n "$(find "$dir" -maxdepth 0 -perm -0002 2>/dev/null)" ] || \
       [ -n "$(find "$dir" -maxdepth 0 -perm -0020 2>/dev/null)" ]; then
        echo "refusing to build under $dir: its group or everyone can write there, and a file planted there" \
             "can change what the build imports or restores. Set TMPDIR to a directory only you can" \
             "write." >&2
        exit 1
    fi
    [ "$dir" = "/" ] && break
    dir=$(dirname "$dir")
done
echo "exporting $commit to $work" >&2

git -C "$root" archive "$commit" | tar -x -C "$work"

# VERIFY the export instead of trusting it. git archive applies attributes, and not only the committed
# .gitattributes: $GIT_DIR/info/attributes and a global attributes file can rewrite line endings, drop a
# file with export-ignore, or run a smudge filter. Comparing each exported file with its blob, with
# filters off, catches every one of those, and a missing or extra file besides.
python3 - "$root" "$commit" "$work" <<'PY'
import os, subprocess, sys
root, commit, work = sys.argv[1:]
listing = subprocess.run(["git", "-C", root, "ls-tree", "-r", "-z", "--full-tree", commit],
                         capture_output=True, check=True).stdout.split(b"\0")
expected = {}
for entry in filter(None, listing):
    meta, path = entry.split(b"\t", 1)
    mode, kind, blob = meta.split()
    if kind == b"blob":
        expected[os.fsdecode(path)] = (mode.decode(), blob.decode())
exported = set()
for top, dirs, files in os.walk(work):
    for name in files + [d for d in dirs if os.path.islink(os.path.join(top, d))]:
        exported.add(os.path.relpath(os.path.join(top, name), work))
problems = [f"missing: {p}" for p in sorted(set(expected) - exported)]
problems += [f"not in {commit[:12]}: {p}" for p in sorted(exported - set(expected))]
regular = [p for p in sorted(expected) if p in exported and expected[p][0] != "120000"]
hashed = subprocess.run(["git", "-C", root, "hash-object", "--no-filters", "--stdin-paths"],
                        input="\n".join(os.path.join(work, p) for p in regular) + "\n",
                        capture_output=True, text=True, check=True).stdout.split()
for path, got in zip(regular, hashed):
    mode, blob = expected[path]
    if got != blob:
        problems.append(f"bytes differ from HEAD: {path}")
    elif (mode == "100755") != os.access(os.path.join(work, path), os.X_OK):
        problems.append(f"executable bit differs from HEAD: {path}")
# Symlinks are refused outright, even one that matches HEAD's blob. The blob is the link TEXT, and the
# compiler follows the link, so a committed link to a file outside the export would compile bytes no
# git object holds while HEAD:src stayed the same.
problems += [f"symlink, which the build would follow to bytes git does not hold: {p}"
             for p in sorted(expected) if expected[p][0] == "120000"]
if problems:
    print(f"the export of {commit[:12]} cannot vouch for a record. Usually a local attribute "
          "(.git/info/attributes, core.attributesFile) or a filter is rewriting what git archive writes; "
          "a symlink, or paths differing only in case on a case-insensitive disk, also land here:",
          *problems[:20], sep="\n  ", file=sys.stderr)
    sys.exit(1)
print(f"verified {len(expected)} files against {commit[:12]}", file=sys.stderr)
PY

# Written only here, only after verification. The harness refuses to report an export stamp without it,
# so a working-tree build that carries the stamp, because HarnessExportOf was set in a shell, cannot pass
# as an export even when its output was copied out of the checkout.
printf '%s\n' "$commit" > "$work/.export-verified"
cp "$settings" "$work/tools/conformance-harness/appsettings.Local.json"
cd "$work/tools/conformance-harness"

# Every way MSBuild reaches outside the project, turned off. This repository has no
# Directory.Build.targets or Directory.Packages.props, so their upward search would leave the export;
# -noAutoResponse stops it reading a Directory.Build.rsp from any directory above; the four
# ImportUserLocations switches stop it importing whatever sits in the user's MSBuild extensions folder;
# the two Discover switches stop the compiler reading .editorconfig and .globalconfig from every
# directory above each source file, which this repository has none of.
# env -i with an allowlist drops every other variable, because MSBuild reads the environment as
# properties: CustomBeforeMicrosoftCommonTargets, or HarnessExportOf itself, would otherwise apply.
# Still out of reach from here: the package cache and NuGet sources, which a record does not describe
# either.
clean_env() {
    env -i HOME="$HOME" PATH="$PATH" TMPDIR="${TMPDIR:-}" LANG="${LANG:-C.UTF-8}" "$@"
}
clean_env dotnet build conformance-harness.csproj --no-incremental -noAutoResponse \
    -p:HarnessExportOf="$commit" \
    -p:ImportDirectoryBuildTargets=false -p:ImportDirectoryPackagesProps=false \
    -p:ImportUserLocationsByWildcardBeforeMicrosoftCommonProps=false \
    -p:ImportUserLocationsByWildcardAfterMicrosoftCommonProps=false \
    -p:ImportUserLocationsByWildcardBeforeMicrosoftCommonTargets=false \
    -p:ImportUserLocationsByWildcardAfterMicrosoftCommonTargets=false \
    -p:DiscoverEditorConfigFiles=false -p:DiscoverGlobalAnalyzerConfigFiles=false

# The built assembly, run directly: `dotnet run` would evaluate the project again, and could take a
# stray argument as the application's. Development is what launchSettings.json gives `dotnet run`.
#
# env is backgrounded DIRECTLY, not through clean_env: a backgrounded shell function runs in a forked
# subshell, so $! would be that subshell, cleanup would kill it, and dotnet would carry on holding the
# port as an orphan. env execs dotnet, so here $! IS the harness.
env -i HOME="$HOME" PATH="$PATH" TMPDIR="${TMPDIR:-}" LANG="${LANG:-C.UTF-8}" \
    ASPNETCORE_ENVIRONMENT=Development dotnet bin/Debug/net10.0/conformance-harness.dll &
pid=$!
wait "$pid"
