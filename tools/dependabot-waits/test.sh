#!/usr/bin/env bash
# What belongs here: the tests for check.sh, against a gh stub on PATH that prints a fixed pull request list
# and logs every call, so nothing real is assigned or commented on. dependabot-waits.yml runs this on every
# pull request that touches tools/dependabot-waits. Every branch, time and number below is made up.
#
#   tools/dependabot-waits/test.sh
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT

mkdir -p "$T/bin"
cat >"$T/bin/gh" <<'EOF'
#!/usr/bin/env bash
echo "gh $*" >>"$STUB_LOG"
case "$1 $2" in
  "pr list") [ -n "${STUB_LIST_FAILS:-}" ] && exit 1; printf '%s' "$STUB_PRS" ;;
esac
EOF
chmod +x "$T/bin/gh"
export PATH="$T/bin:$PATH" GITHUB_REPOSITORY=owner/repo STUB_LOG="$T/log"
# A Tuesday at 05:41 UTC, a scheduled run's time, so the ages below are exact.
NOW=$(date -u -d 2026-11-17T05:41:00Z +%s); export NOW

OLD=2026-10-30T05:41:00Z      # 18 days
MONDAY=2026-11-09T22:30:00Z   # 7.3 days: a Monday-night pull request, the Tuesday after next
EDGE=2026-11-10T05:41:00Z     # exactly 7 days, not yet too long
MID=2026-11-12T00:00:00Z
NEW=2026-11-14T05:41:00Z      # 3 days
NEW_10S=2026-11-14T05:41:10Z  # ten seconds after NEW, inside the replacement window
NEW_20M=2026-11-14T06:01:00Z  # twenty minutes after NEW, outside it

# open <number> <branch> <createdAt> [assignees json]
open() { printf '{"number":%s,"headRefName":"%s","createdAt":"%s","closedAt":null,"mergedAt":null,"state":"OPEN","assignees":[%s]}' "$1" "$2" "$3" "${4:-}"; }
# closed <number> <branch> <createdAt> <closedAt>: closed unmerged
closed() { printf '{"number":%s,"headRefName":"%s","createdAt":"%s","closedAt":"%s","mergedAt":null,"state":"CLOSED","assignees":[]}' "$@"; }
# merged <number> <branch> <createdAt> <mergedAt>
merged() { printf '{"number":%s,"headRefName":"%s","createdAt":"%s","closedAt":"%s","mergedAt":"%s","state":"MERGED","assignees":[]}' "$1" "$2" "$3" "$4" "$4"; }

G=dependabot/some_group-0a1b2c3d4e        # a group, hash suffix
G2=dependabot/some_group-5f6a7b8c9d       # the same group, a later update
D=dependabot/nuget/tests/example.package-10.1.1
D2=dependabot/nuget/tests/example.package-10.1.2
M=dependabot/nuget/src/Example/multi-0a1b2c3d4e
M2=dependabot/nuget/src/Example/multi-5f6a7b8c9d

pass=0; fail=0
# run <name> <expected exit> <mode> <prs json> [extended regex that must appear in the gh log]...
# A pattern starting with ! must not appear.
run() {
    local name=$1 want=$2 mode=$3 prs=$4; shift 4
    : >"$STUB_LOG"
    STUB_PRS=$prs MODE=$mode "$HERE/check.sh" >"$T/out" 2>&1; local got=$?
    local ok=1
    [ "$got" = "$want" ] || { ok=0; echo "  exit $got, wanted $want"; }
    for p in "$@"; do
        if [ "${p#!}" != "$p" ]; then grep -qE -- "${p#!}" "$STUB_LOG" && { ok=0; echo "  log has: ${p#!}"; }
        else grep -qE -- "$p" "$STUB_LOG" || { ok=0; echo "  log lacks: $p"; }; fi
    done
    if [ $ok = 1 ]; then pass=$((pass+1)); echo "ok   $name"
    else fail=$((fail+1)); echo "FAIL $name"; sed 's/^/  | /' "$T/out" "$STUB_LOG"; fi
}
assign() { printf 'api -X POST repos/owner/repo/issues/%s/assignees -f assignees\\[\\]=tdwd' "$1"; }
comment() { printf 'api -X POST repos/owner/repo/issues/%s/comments -f body=@tdwd' "$1"; }

run "no pull requests" 0 report '[]' '!api'
run "a fresh open pull request" 0 report "[$(open 1 $D $NEW)]" '!api'
run "exactly the limit is not too long" 0 report "[$(open 1 $D $EDGE)]" '!api'
run "opened Monday night, flagged the Tuesday after next" 1 report "[$(open 2 $G $MONDAY)]" \
    "$(comment 2) .*waited 7 days"
run "a long wait and unassigned: assigned, commented on, fails" 1 report "[$(open 3 $G $OLD)]" \
    "$(assign 3)" "$(comment 3) .*waited 18 days"
run "a group's wait counts the pull request it replaced" 1 report \
    "[$(open 4 $G2 $NEW),$(closed 3 $G $OLD $NEW)]" "$(comment 4) .*waited 18 days"
run "a dependency's wait counts the version it replaced" 1 report \
    "[$(open 8 $D2 $NEW_10S),$(closed 7 $D $OLD $NEW)]" "$(comment 8) .*waited 18 days"
run "a replacement chain counts back to its first" 1 report \
    "[$(open 9 $D2 $NEW),$(closed 8 $D $MID $NEW),$(closed 7 $D $OLD $MID)]" "$(comment 9) .*waited 18 days"
run "a pull request a person closed ends the wait" 0 report \
    "[$(open 8 $D2 $NEW),$(closed 7 $D $OLD $EDGE)]" '!api'
run "a close twenty minutes before the next opening is not a replacement" 0 report \
    "[$(open 8 $D2 $NEW_20M),$(closed 7 $D $OLD $NEW)]" '!api'
run "a merge ends the wait" 0 report "[$(open 4 $G2 $NEW),$(merged 3 $G $OLD $MID)]" '!api'
run "a merge restarts the wait for the replacements after it" 0 report \
    "[$(open 5 $G2 $NEW),$(closed 4 $G $EDGE $NEW),$(merged 3 $G $OLD $EDGE)]" "!api"
run "one dependency's old wait does not age another's" 0 report \
    "[$(open 8 $D $NEW),$(closed 3 $G $OLD $NEW)]" '!api'
run "another dependency's merge does not end a wait" 1 report \
    "[$(open 8 $D $OLD),$(merged 3 $G $OLD $MID)]" "$(comment 8)" '!issues/3/'
run "a long wait with nothing open has nothing to comment on" 0 report "[$(closed 3 $G $OLD $MID)]" '!api'
run "already assigned: commented on only" 1 report "[$(open 3 $G $OLD '{"login":"tdwd"}')]" \
    '!issues/3/assignees' "$(comment 3)"
run "every waiting dependency is commented on" 1 report \
    "[$(open 7 $G $OLD),$(open 8 $D $OLD)]" "$(comment 7)" "$(comment 8)"
run "multi-package pull requests are never chained" 0 report \
    "[$(open 6 $M2 $NEW),$(closed 5 $M $OLD $NEW)]" '!api'
run "a multi-package pull request's own wait is still flagged" 1 report "[$(open 6 $M $OLD)]" \
    "$(comment 6) .*waited 18 days"
run "a v-prefixed version is one dependency" 1 report \
    "[$(open 5 dependabot/docker_compose/compose/example/app-v1.33.1 $NEW),$(closed 4 dependabot/docker_compose/compose/example/app-v1.32.0 $OLD $NEW)]" \
    "$(comment 5) .*waited 18 days"
run "a version with a tag suffix is one dependency" 1 report \
    "[$(open 5 dependabot/docker/web/server-2.11.9-alpine $NEW),$(closed 4 dependabot/docker/web/server-2.11.8-alpine $OLD $NEW)]" \
    "$(comment 5) .*waited 18 days"
run "a group hash starting with a letter is one group" 1 report \
    "[$(open 5 dependabot/github_actions/actions-e40781d787 $NEW),$(closed 4 dependabot/github_actions/actions-a298f52aab $OLD $NEW)]" \
    "$(comment 5) .*waited 18 days"
run "a hyphen inside a dependency's name is part of it" 1 report \
    "[$(open 5 dependabot/github_actions/actions/attest-build-provenance-1.4.1 $NEW),$(closed 4 dependabot/github_actions/actions/attest-build-provenance-1.4.0 $OLD $NEW)]" \
    "$(comment 5) .*waited 18 days"
run "a digit after a hyphen inside a name is part of it" 0 report \
    "[$(open 5 dependabot/npm_and_yarn/utf-8-validate-6.0.5 $NEW),$(closed 4 dependabot/npm_and_yarn/utf-16-decoder-1.0.0 $OLD $NEW)]" '!api'
run "dependencies sharing a first word are separate" 0 report \
    "[$(open 5 dependabot/github_actions/actions/attest-build-provenance-1.4.1 $NEW),$(closed 4 dependabot/github_actions/actions/attest-sbom-2.0.0 $OLD $NEW)]" '!api'
run "a dependency whose name extends another's is its own" 0 report \
    "[$(open 5 dependabot/npm_and_yarn/web/tailwindcss/vite-4.3.5 $NEW),$(closed 4 dependabot/npm_and_yarn/web/tailwindcss-4.3.5 $OLD $NEW)]" '!api'
run "dry-run changes nothing but still fails" 1 dry-run "[$(open 3 $G $OLD)]" '!api'
STUB_LIST_FAILS=1 run "a list that fails fails the run" 1 report '[]' '!api'

echo "$pass passed, $fail failed"
[ $fail = 0 ]
