#!/usr/bin/env bash
# What belongs here: the weekly check that no Dependabot update is left waiting unmerged. Run by
# .github/workflows/dependabot-waits.yml. Several repositories carry this file, the same in each, at
# this path, so it names none of them; each repository's own docs record what happened there.
#
#   MODE=dry-run tools/dependabot-waits/check.sh   # print what it would do, change nothing
#   MODE=report  tools/dependabot-waits/check.sh   # the scheduled run
#
# Why it exists: a dependency update is in use only once its pull request merges, and an open one tells
# nobody. Worse, with a group spanning two ecosystems Dependabot was seen deferring to the open pull
# request ("Deferring creation of a new pull request. The existing pull request will update in a
# separate job"), updating it in no job, and dropping the other ecosystem's update with no pull request,
# so one unmerged pull request held every later update back for weeks. GitHub's docs say Dependabot
# rebases a pull request that conflicts, which is not what those logs showed, so this checks the outcome.
#
# WHAT IS MEASURED: how long each dependency's or group's update has waited unmerged, not how old the
# open pull request is. Dependabot replaces a pull request when versions change, which restarts its
# age, so updates once waited over three weeks across two pull requests while neither was ever eight
# days old on a Tuesday. A pull request's dependency or group is its branch name without the version or
# group hash at its end: dependabot/nuget/tests/example.package-10.1.1 and -10.1.2 are one, and so are
# dependabot/some_group-0a1b2c3d4e and -5f6a7b8c9d. A multi-package pull request (a branch ending
# multi-<hash>) is the exception: there the hash is all that tells one set of packages from another, so
# each is its own and is measured from its own opening.
#
# An open pull request's wait starts at the oldest one it replaced, following back only replacements:
# an earlier unmerged pull request of the same dependency or group that closed within REPLACED_WITHIN
# seconds of the next one opening, which is how Dependabot closes the one it replaces. A merge, or a
# pull request a person closed (the update folded into their own pull request, or not wanted), ends that
# wait, and the next one starts afresh. Two cases are read wrongly, both rare: a person's close followed
# within REPLACED_WITHIN by Dependabot's next version reads as a replacement, and a single-package pull
# request replaced by a multi-package one is not followed, so that wait is under-counted.
#
# When a wait passes MAX_DAYS and a pull request of it is open, that pull request is assigned to
# $ASSIGNEE and commented on with an @mention, which is what reaches a person. A run each Tuesday flags a
# wait 7 to 14 days after it began, and the comment repeats each week until the wait ends.
#
# THE RUN PASSES WHEN IT HAS TOLD SOMEONE, and fails only when it could not: the list could not be read,
# or a call to assign or comment failed. A scheduled run's result lands on main's latest commit, so failing
# for every wait painted main red in every repository with one, and its notification reaches only the
# workflow's creator or whoever last edited its cron line. A red run therefore means the alert did not get
# through, which is the one case nobody else would hear about.
set -uo pipefail

MAX_DAYS=7
MODE="${MODE:-dry-run}"
# The account that reads these repositories' notifications.
ASSIGNEE=tdwd
# At the very end of a branch name, a version (1.2.3, v1.33.1, 2.11.9-alpine) or a group's ten-character
# hash. Anchored at the end, so a name with a digit after a hyphen (utf-8-validate-6.0.5) keeps it.
SUFFIX='-(v?[[:digit:]][[:alnum:]._+]*(-[[:alpha:]][[:alnum:].]*)?|[[:xdigit:]]{10})$'
# Dependabot closes a replaced pull request within seconds of opening the next (twelve at most, either
# way, over every replacement these repositories had by 2026-11-20); two minutes is a wide margin that
# still leaves little room for a person's close to pass as one.
REPLACED_WITHIN=120
NOW="${NOW:-$(date -u +%s)}"

listed=$(gh pr list --repo "$GITHUB_REPOSITORY" --author app/dependabot --state all --limit 500 \
    --json number,headRefName,createdAt,closedAt,mergedAt,state,assignees) \
    || { echo "::error::could not list pull requests"; exit 1; }

# One line per open pull request whose wait is too long: number, whole days waited, whether $ASSIGNEE is
# already assigned. Each dependency's or group's pull requests are walked oldest first, carrying the
# start of the current wait forward only across replacements.
stale=$(jq -r --arg sfx "$SUFFIX" --arg who "$ASSIGNEE" --argjson max "$MAX_DAYS" --argjson now "$NOW" \
        --argjson within "$REPLACED_WITHIN" '
    def t: if . then fromdateiso8601 else null end;
    def key: .headRefName as $b | ($b | sub($sfx; "")) as $k | if ($k | endswith("/multi")) then $b else $k end;
    group_by(key)[]
    | sort_by(.createdAt)
    | reduce .[] as $p ({prev: null, since: null, open: []};
        ($p.createdAt | t) as $c
        | (if .prev != null and .prev.mergedAt == null and .prev.closedAt != null
              and (($c - (.prev.closedAt | t)) | fabs) <= $within
           then .since else $c end) as $since
        | .open += (if $p.state == "OPEN" then [{p: $p, since: $since}] else [] end)
        | .since = $since | .prev = $p)
    | .open[]
    | select(($now - .since) > $max * 86400)
    | "\(.p.number) \((($now - .since) / 86400) | floor) \([.p.assignees[].login] | index($who) != null)"
    ' <<<"$listed") \
    || { echo "::error::could not read the pull request list"; exit 1; }

if [ -z "$stale" ]; then
    echo "No Dependabot update has waited unmerged more than $MAX_DAYS days with a pull request open."
    exit 0
fi

# Plain REST calls, which need only the token's issues or pull-requests write. A wait is a warning; a call
# that failed is an error and fails the run, once every pull request has been tried.
failed=0
while read -r number days assigned; do
    echo "::warning::#$number: this update has waited $days days unmerged."
    [ "$MODE" = report ] || { echo "dry-run: would assign #$number to $ASSIGNEE and comment"; continue; }
    if [ "$assigned" != true ]; then
        gh api -X POST "repos/$GITHUB_REPOSITORY/issues/$number/assignees" -f "assignees[]=$ASSIGNEE" >/dev/null \
            || { echo "::error::could not assign #$number"; failed=1; }
    fi
    gh api -X POST "repos/$GITHUB_REPOSITORY/issues/$number/comments" -f body="@$ASSIGNEE this update has waited $days days unmerged, counting any pull request this one replaced, so it is not in use yet. Merge this, or close it if it conflicts, main has moved past it or the update is not wanted, so the next Dependabot run can propose what is current.${RUN_URL:+ ([check]($RUN_URL))}" >/dev/null \
        || { echo "::error::could not comment on #$number"; failed=1; }
done <<<"$stale"
exit $failed
