#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Robin Jarry

set -e -o pipefail

: ${PULL_REQUEST?PULL_REQUEST}
: ${LOGIN?LOGIN}

# get the full URL pointing to the current github action job
job_url() {
	local run_id="$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID"
	local job_id=$(gh api "repos/$run_id/jobs" --jq ".jobs[] | select(.name==\"$GITHUB_JOB\") | .id")
	echo "https://github.com/$run_id/job/$job_id"
}

# post an error message on the pull request
fail() {
	set +e
	gh pr comment $PR_NUMBER -b "error: $1

$JOB_URL"
	exit 1
}

# error trap handler
err() {
	set +e
	gh pr comment $PR_NUMBER -b "error: command \`$BASH_COMMAND\` failed

$JOB_URL"
	exit 1
}

# get the full name of the given github account (may not be available)
user_name() {
	local login=$1
	local name=$(gh api users/$login --jq '.name')
	if [ -z "$name" ] || [ "$name" = null ]; then
		fail "user $login does not expose their full name"
	fi
	echo "$name"
}

# get the email exposed by the given github account (may not be available)
email_from_gh() {
	local login=$1
	gh api users/$login --jq '.email'
}

# get the most recent email used by that person from git history
email_from_git() {
	local name=$1
	git log --pretty=%aE --author="$name" | head -n1
}

# get the email from a github account (fallback to looking at github history)
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

trap err ERR

# gather pull request details
PR_JSON=$(gh api "$PULL_REQUEST")
PR_NUMBER=$(echo "$PR_JSON" | jq -r .number)
BASE_REF=$(echo "$PR_JSON" | jq -r .base.ref)
HEAD_REF=$(echo "$PR_JSON" | jq -r .head.ref)
NUM_COMMITS=$(echo "$PR_JSON" | jq -r .commits)
HEAD_URL=$(echo "$PR_JSON" | jq -r .head.repo.clone_url)
JOB_URL=$(job_url)
tmp=$(mktemp -d)
trap "rm -rf -- $tmp" EXIT

set -x

# ensure that the person that posted the '/apply' comment has push access
perm=$(gh api "repos/$GITHUB_REPOSITORY/collaborators/$LOGIN/permission" --jq '.permission')
if ! [ "$perm" = admin ] && ! [ "$perm" = write ]; then
	fail "user $LOGIN does not have permission to apply PRs (permission: $perm)"
fi

# configure git identity to the person that posted the '/apply' comment
# they will be "committer" of all the rebased commits
GIT_COMMITTER_NAME=$(user_name "$LOGIN")
GIT_COMMITTER_EMAIL=$(user_email "$LOGIN" "$GIT_COMMITTER_NAME")
git config set user.name "$GIT_COMMITTER_NAME"
git config set user.email "$GIT_COMMITTER_EMAIL"
export GIT_COMMITTER_NAME GIT_COMMITTER_EMAIL
rm -f .git/hooks/commit-msg
ln -s ../../devtools/commit-msg .git/hooks/commit-msg

base_sha=$(git log -1 --pretty=%H HEAD)

git remote add head "$HEAD_URL"
git fetch head
git checkout -b "$HEAD_REF" "head/$HEAD_REF"
git branch --set-upstream-to="origin/$BASE_REF"

# fast forward merge the pull request branch on top of the base one
if ! git rebase "origin/$BASE_REF" >"$tmp/rebase" 2>&1; then
	fail "rebase failed:
\`\`\`
$(cat $tmp/rebase)
\`\`\`"
fi

# ensure at least one commit was applied
rebased_sha=$(git log -1 --pretty=%H HEAD)
if [ "$rebased_sha" = "$base_sha" ]; then
	fail "branch commits already merged"
fi

# add a Reviewed-by trailer for every "approved" review
gh api "repos/$GITHUB_REPOSITORY/pulls/$PR_NUMBER/reviews" --paginate \
	--jq '.[] | select(.state=="APPROVED") | .user.login' | sort -u |
while read -r login; do
	name=$(user_name "$login")
	email=$(user_email "$login" "$name")
	echo "Reviewed-by: $name <$email>"
done >> "$tmp/trailers"

# gather all comments that contain Reviewed-by, Acked-by or Tested-by trailers
trailer_re="[[:space:]]*(Reviewed|Acked|Tested)-by:[[:blank:]]+" # trailer key
trailer_re="$trailer_re([[:alpha:]][^<]*[[:alpha:]])[[:blank:]]+" # full name
trailer_re="$trailer_re<?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,})>?[[:space:]]*" # email
gh api "repos/$GITHUB_REPOSITORY/issues/$PR_NUMBER/comments" --paginate --jq '.[].body' |
	sed -En "s/^$trailer_re\$/\\1-by: \\2 <\\3>/p" | sort -u >> "$tmp/trailers"

sort -u "$tmp/trailers" > "$tmp/trailers-uniq"

trailers=""
while read -r line; do
	trailers="$trailers --trailer '$line'"
done < "$tmp/trailers-uniq"

if [ -n "$trailers" ]; then
	# rewrite all commit messages, appending trailers
	# hooks/commit-msg will remove duplicates and ensure correct ordering
	GIT_TRAILER_DEBUG=1 git rebase "origin/$BASE_REF" \
		--exec "git commit -C HEAD --no-edit --amend $trailers"
	git log --pretty=fuller "origin/$BASE_REF.."
fi

# fast-forward merge the rebased branch with added trailers and push it manually
git checkout "$BASE_REF"
git merge --ff-only "$HEAD_REF"
git push origin "$BASE_REF"

# post a comment to identify the new HEAD commit id
sha=$(git log -1 --pretty=%H "origin/$BASE_REF")
gh pr comment "$PR_NUMBER" -b "Pull request applied with git trailers: $sha

$(job_url)"

# 'gh pr merge --rebase' will do nothing since the branch was already pushed
# bypass the check and invoke the API endpoint directly
gh api -X PUT "repos/$GITHUB_REPOSITORY/pulls/$PR_NUMBER/merge" \
	-f merge_method=rebase || gh pr close $PR_NUMBER
