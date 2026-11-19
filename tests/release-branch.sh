#!/bin/sh -e
# Drives release-branch.sh against a local bare remote and a fake gh, one case per situation it handles.

ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
# The user's git configuration, such as commit signing, stays out of the cases.
GIT_CONFIG_GLOBAL=/dev/null
GIT_CONFIG_NOSYSTEM=1
export GIT_CONFIG_GLOBAL GIT_CONFIG_NOSYSTEM

BOT_EMAIL="1+release[bot]@users.noreply.github.com"
OLD=sqlite3mc/v2.7.0
NEW=sqlite3mc/v2.7.1
failed=""

mkdir "$WORK/bin"
cat > "$WORK/bin/gh" <<'EOF'
#!/bin/sh -e
# Answers release-branch.sh's gh calls from the files in $GH_STATE, logging every write.
prs=$GH_STATE/prs
comments=$GH_STATE/comments
sub="$1 $2"
shift 2
case $sub in
"pr list")
    while [ $# -gt 0 ]; do [ "$1" != --head ] || head=$2; shift; done
    awk -v head="$head" '$2 == head && $3 == "open" { print $1; exit }' "$prs" ;;
"pr view")
    awk -F '\t' -v n="$1" '$1 == n { print $2 }' "$comments" ;;
"pr comment")
    printf '%s\t%s\n' "$1" "$3" >> "$comments"
    echo "comment $1 $3" >> "$GH_STATE/log" ;;
"pr close")
    printf '%s\t%s\n' "$1" "$3" >> "$comments"
    awk -v n="$1" '$1 == n { $3 = "closed" } { print }' "$prs" > "$prs.new"
    mv "$prs.new" "$prs"
    echo "close $1 $3" >> "$GH_STATE/log" ;;
"pr create")
    while [ $# -gt 0 ]; do [ "$1" != --head ] || head=$2; shift; done
    echo "$(($(wc -l < "$prs") + 1)) $head open" >> "$prs"
    echo "create $head" >> "$GH_STATE/log" ;;
*)
    echo "fake gh: unexpected gh $sub $*" >&2
    exit 1 ;;
esac
EOF
chmod +x "$WORK/bin/gh"

# Commits as a human in the current directory.
human_commit() {
    git add -A
    GIT_AUTHOR_NAME=Luca GIT_AUTHOR_EMAIL=luca@example.com GIT_COMMITTER_NAME=Luca \
        GIT_COMMITTER_EMAIL=luca@example.com git commit --quiet "$@"
}

# Starts case $1 with a remote whose main holds a vendored 2.6.1 and no release branch.
start() {
    CASE=$WORK/$1
    mkdir -p "$CASE/gh" "$CASE/seed"
    : > "$CASE/gh/prs"
    : > "$CASE/gh/comments"
    : > "$CASE/gh/log"
    git init --quiet --bare -b main "$CASE/remote.git"
    cd "$CASE/seed"
    git init --quiet -b main
    mkdir src sqlite3mc smoke fuzz
    echo 'pub const SQLITE_VERSION: &str = "3.54.1";' > src/lib.rs
    echo "release 2.6.1" > sqlite3mc/amalgamation.c
    for file in Cargo.toml Cargo.lock smoke/Cargo.lock fuzz/Cargo.lock upgrade.sh README.md; do echo "$file" > "$file"; done
    human_commit -m "Vendor SQLite3MC 2.6.1"
    git push --quiet "$CASE/remote.git" main
}

# Runs the bot on a fresh checkout of main, vendoring release $1 with amalgamation text $2.
bot() {
    cd "$CASE"
    rm -rf "$CASE/run"
    git clone --quiet "$CASE/remote.git" "$CASE/run"
    cd "$CASE/run"
    git config user.name "release[bot]"
    git config user.email "$BOT_EMAIL"
    echo "${2:-release $1}" > sqlite3mc/amalgamation.c
    cp "$ROOT/release-branch.sh" .
    PATH="$WORK/bin:$PATH" GH_STATE="$CASE/gh" ./release-branch.sh "$1" > "$CASE/out" 2>&1 ||
        { echo "release-branch.sh $1 failed:"; cat "$CASE/out"; }
}

# Commits file $2 with text $3 as a human on remote branch $1, merging main in first when $4 is merge.
push_as_human() {
    cd "$CASE"
    rm -rf "$CASE/human"
    git clone --quiet --branch "$1" "$CASE/remote.git" "$CASE/human"
    cd "$CASE/human"
    if [ "${4:-}" = merge ]; then
        GIT_AUTHOR_NAME=Luca GIT_AUTHOR_EMAIL=luca@example.com GIT_COMMITTER_NAME=Luca \
            GIT_COMMITTER_EMAIL=luca@example.com git merge --quiet --no-edit origin/main
    fi
    echo "$3" > "$2"
    human_commit -m "Change $2 on $1"
    git push --quiet origin "$1"
}

remote() { git --git-dir="$CASE/remote.git" "$@"; }
tip() { remote rev-parse -q --verify "refs/heads/$1" || true; }
subjects() { remote log --format=%s "main..$1" | tr '\n' '|'; }
logged() { grep -c "$1" "$CASE/gh/log" || true; }

# Records a failure of case $1, described by $2, unless the observed $3 equals the wanted $4.
expect() {
    if [ "$3" != "$4" ]; then
        printf 'FAIL  %s  %s\n    got:  %s\n    want: %s\n' "$1" "$2" "$3" "$4"
        sed 's/^/    /' "$CASE/out"
        failed="$failed $1"
    fi
}

start new-branch
bot 2.7.1
expect new-branch "the release is one commit on main" "$(subjects $NEW)" "Vendor SQLite3MC 2.7.1 on SQLite 3.54.1|"
expect new-branch "the branch holds the release" "$(remote show $NEW:sqlite3mc/amalgamation.c)" "release 2.7.1"
expect new-branch "its pull request opens" "$(logged "^create $NEW$")" 1

start unchanged
bot 2.7.1
before=$(tip $NEW)
bot 2.7.1
expect unchanged "the branch stays" "$(tip $NEW)" "$before"
expect unchanged "no second pull request opens" "$(logged "^create")" 1

start release-changed
bot 2.7.1 "release 2.7.1 first upload"
bot 2.7.1 "release 2.7.1 second upload"
expect release-changed "the branch holds the new upload" "$(remote show $NEW:sqlite3mc/amalgamation.c)" "release 2.7.1 second upload"
expect release-changed "the release is still one commit" "$(remote rev-list --count main..$NEW)" 1

start main-moved
bot 2.7.1
push_as_human main README.md "main moved"
bot 2.7.1
expect main-moved "the branch sits on the current main" "$(remote rev-parse $NEW^)" "$(tip main)"
expect main-moved "the release is still one commit" "$(remote rev-list --count main..$NEW)" 1

start fix-kept
bot 2.7.1
push_as_human $NEW fix.txt fixed
before=$(tip $NEW)
bot 2.7.1
expect fix-kept "the branch with its fix stays" "$(tip $NEW)" "$before"

start fix-kept-release-changed
bot 2.7.1
push_as_human $NEW fix.txt fixed
before=$(tip $NEW)
bot 2.7.1 "release 2.7.1 second upload"
bot 2.7.1 "release 2.7.1 second upload"
expect fix-kept-release-changed "the branch with its fix stays" "$(tip $NEW)" "$before"
expect fix-kept-release-changed "one comment names the changed file" "$(logged "^comment 1 .*sqlite3mc/amalgamation.c")" 1

start release-commit-amended
bot 2.7.1
cd "$CASE" && git clone --quiet --branch $NEW "$CASE/remote.git" amend && cd amend
GIT_COMMITTER_NAME=Luca GIT_COMMITTER_EMAIL=luca@example.com git commit --quiet --amend -m "Vendor SQLite3MC 2.7.1, amended"
git push --quiet --force origin $NEW
before=$(tip $NEW)
bot 2.7.1
bot 2.7.1
expect release-commit-amended "the amended branch stays" "$(tip $NEW)" "$before"
expect release-commit-amended "one comment names the vendored files" "$(logged "^comment 1 .*sqlite3mc/amalgamation.c")" 1

start fix-replayed
bot 2.7.1
push_as_human $NEW fix.txt fixed
push_as_human main README.md "main moved"
bot 2.7.1
expect fix-replayed "the fix sits on the release on the current main" "$(remote rev-parse $NEW~2)" "$(tip main)"
expect fix-replayed "the fix keeps its text" "$(remote show $NEW:fix.txt)" fixed
expect fix-replayed "the fix keeps its author" "$(remote log -1 --format=%ae $NEW)" luca@example.com
expect fix-replayed "the release is updated" "$(subjects $NEW)" "Change fix.txt on $NEW|Vendor SQLite3MC 2.7.1 on SQLite 3.54.1|"

start fix-conflicts-with-main
bot 2.7.1
push_as_human $NEW README.md "branch readme"
push_as_human main README.md "main readme"
before=$(tip $NEW)
bot 2.7.1
bot 2.7.1
expect fix-conflicts-with-main "the branch stays" "$(tip $NEW)" "$before"
expect fix-conflicts-with-main "one comment names the commit" "$(logged "^comment 1 .*$before")" 1

start merge-commit
bot 2.7.1
push_as_human main README.md "main moved"
push_as_human $NEW fix.txt fixed merge
push_as_human main upgrade.sh "main moved again"
before=$(tip $NEW)
bot 2.7.1
bot 2.7.1
expect merge-commit "the branch stays" "$(tip $NEW)" "$before"
expect merge-commit "one comment names the merge" "$(logged "^comment 1 .*$(remote rev-parse $NEW^)")" 1

start superseded
bot 2.7.0
bot 2.7.1
expect superseded "the old branch is deleted" "$(tip $OLD)" ""
expect superseded "the old pull request closes" "$(logged "^close 1 Superseded by SQLite3MC 2.7.1.$")" 1
expect superseded "the new branch holds only its release" "$(remote rev-list --count main..$NEW)" 1

start superseded-fix-carried
bot 2.7.0
push_as_human $OLD fix.txt fixed
bot 2.7.1
expect superseded-fix-carried "the fix moves to the new branch" "$(subjects $NEW)" "Change fix.txt on $OLD|Vendor SQLite3MC 2.7.1 on SQLite 3.54.1|"
expect superseded-fix-carried "the old branch is deleted" "$(tip $OLD)" ""
expect superseded-fix-carried "the old pull request closes naming the new branch" "$(logged "^close 1 .*$NEW")" 1

start superseded-fix-conflicts
bot 2.7.0
push_as_human $OLD sqlite3mc/amalgamation.c "release 2.7.0 patched"
before=$(tip $OLD)
bot 2.7.1
bot 2.7.1
expect superseded-fix-conflicts "the new branch holds only its release" "$(remote rev-list --count main..$NEW)" 1
expect superseded-fix-conflicts "the old branch stays" "$(tip $OLD)" "$before"
expect superseded-fix-conflicts "the old pull request closes once, naming the commit" "$(logged "^close 1 .*$before")" 1
expect superseded-fix-conflicts "the closed pull request gets no further comment" "$(logged "^comment 1")" 0

[ -z "$failed" ] || { echo "Failed:$failed" >&2; exit 1; }
echo "pass  every release branch case"
