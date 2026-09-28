#!/bin/sh
# The one definition of "the src/ tree" for conformance runs: the harness build stamps it and
# run-plan.py compares against it, so both sides compute it here and nowhere else.
#
# Prints the git tree id of src/ AS IT IS ON DISK, uncommitted changes included, without touching the
# real index or any ref. It does write loose objects, which git collects in its own time. A throwaway index is seeded from HEAD, the working src/ is added to it, and the subtree is
# written as an object. Equal to HEAD:src exactly when src/ is clean.
set -eu
root=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
index=$(mktemp)
trap 'rm -f "$index"' EXIT
GIT_INDEX_FILE="$index" git -C "$root" read-tree HEAD
GIT_INDEX_FILE="$index" git -C "$root" add -A -- src
GIT_INDEX_FILE="$index" git -C "$root" write-tree --prefix=src/
