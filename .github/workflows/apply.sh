#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Robin Jarry

: ${PULL_REQUEST?PULL_REQUEST}
: ${LOGIN?LOGIN}

job_url() {
	set +x
	local run_id="$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID"
	local job_id=$(gh api "repos/$run_id/jobs" --jq ".jobs[] | select(.name==\"$GITHUB_JOB\") | .id")
	echo "https://github.com/$run_id/job/$job_id"
	set -x
}

fail() {
	set +e
	gh pr comment $PR_NUMBER -b "error: $*

$JOB_URL"
	exit 1
}

err() {
	set +e
	gh pr comment $PR_NUMBER -b "error: command \`$BASH_COMMAND\` failed

$JOB_URL"
	exit 1
}

user_name() {
	local login=$1
	local name=$(gh api users/$login --jq '.name')
	if [ -z "$name" ] || [ "$name" = null ]; then
		fail "user $login does not expose their full name"
	fi
	echo "$name"
}

email_from_gh() {
	local login=$1
	gh api users/$login --jq '.email'
}

email_from_git() {
	local name=$1
	git shortlog -se -w0 --group=author --group=committer \
		--group=trailer:acked-by --group=trailer:reviewed-by \
		--group=trailer:reported-by --group=trailer:signed-off-by \
		--group=trailer:tested-by HEAD |
	sed -En "s/^[[:space:]]+[0-9]+[[:space:]]+$name <([^@]+@[^>]+)>$/\\1/p"
}

user_email() {
	local login=$1
	local name=$2
	local email=$(email_from_gh "$login")
	if [ -z "$email" ] || [ "$email" = null ]; then
		email=$(email_from_git "$name")
		if [ -z "$email" ]; then
			fail "user $login does not expose their email and is unknown from git history"
		fi
	fi
	echo "$email"
}

set -xEe -o pipefail
trap err ERR

perm=$(gh api "repos/$GITHUB_REPOSITORY/collaborators/$LOGIN/permission" --jq '.permission')
if ! [ "$perm" = admin ] && ! [ "$perm" = write ]; then
	fail "user $LOGIN does not have permission to apply PRs (permission: $perm)"
fi

PR_JSON=$(gh api "$PULL_REQUEST")
PR_NUMBER=$(echo "$PR_JSON" | jq -r .number)
PR_BASE_REF=$(echo "$PR_JSON" | jq -r .base.ref)
PR_HEAD_REF=$(echo "$PR_JSON" | jq -r .head.ref)
PR_HEAD_URL=$(echo "$PR_JSON" | jq -r .head.repo.clone_url)
JOB_URL=$(job_url)

name=$(user_name "$LOGIN")
email=$(user_email "$LOGIN" "$name")
git config set user.name "$name"
git config set user.email "$email"

git remote add pr $PR_HEAD_URL
git fetch pr
git checkout -t pr/$PR_HEAD_REF

tmp=$(mktemp -d)
trap "rm -rf -- $tmp" EXIT

gh api "repos/$GITHUB_REPOSITORY/pulls/$PR_NUMBER/reviews" --paginate \
	--jq '.[] | select(.state=="APPROVED") | .user.login' | sort -u |
while read -r login; do
	name=$(user_name "$login")
	email=$(user_email "$login" "$name")
	echo "Reviewed-by: $name <$email>"
done >> "$tmp/trailers"

gh api "repos/$GITHUB_REPOSITORY/issues/$PR_NUMBER/comments" --paginate \
	--jq '.[].body | select(test("^(Acked-by|Tested-by|Reviewed-by|Reported-by):\\s*"))' >> "$tmp/trailers"

git log --pretty=fuller $PR_BASE_REF..$PR_HEAD_REF

amend="git log -1 --pretty=%B > $tmp/msg"
amend="$amend && devtools/commit-msg $tmp/msg $tmp/trailers"
amend="$amend && git commit --amend -F $tmp/msg --no-edit"
git rebase $PR_BASE_REF --exec "git log -1 --pretty='adding trailers to %h %s' && $amend"

git log --pretty=fuller $PR_BASE_REF..$PR_HEAD_REF

git checkout $PR_BASE_REF
git merge --ff-only $PR_HEAD_REF
git push origin $PR_BASE_REF

gh pr comment $PR_NUMBER -b "Pull request applied with git trailers: $(git log -1 --pretty=%H)

$(job_url)"

gh api -X PUT "repos/$GITHUB_REPOSITORY/pulls/$PR_NUMBER/merge" \
	-f merge_method=rebase || gh pr close $PR_NUMBER
