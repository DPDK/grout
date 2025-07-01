#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Robin Jarry

import json
import os
import sys

import openai
import requests

openai.api_key = os.environ["OPENAI_API_KEY"]
REPO = os.environ["REPO"]
PR_NUMBER = os.environ["PR_NUMBER"]
GITHUB_TOKEN = os.environ["GITHUB_TOKEN"]
COMMIT_ID = os.environ["COMMIT_ID"]
DIFF_FILE = os.environ["DIFF_FILE"]

with open(DIFF_FILE) as f:
    diff = f.read()

# Split into file hunks
comments = []

prompt = f"""You are an expert C developer reviewing a GitHub pull request.

Focus on:
- Memory safety (e.g., buffer overflows, pointer misuse)
- Correctness (null checks, type safety, missing error handling)
- Code clarity and clean style
- Use of standard idioms and conventions (C23)

Only provide helpful, relevant comments.
Be brief but clear.
Only include issues worth commenting.
Never suggest to add code comments.

**IMPORTANT: OUTPUT PURE JSON WITHOUT MARKDOWN SYNTAX.**

Provide a list of concise per-file inline comments in JSON format. Example:

[{{"path": "modules/infra/control/nexthop.c", "line": 42, "comment": "Return value of malloc is not checked."}}, {{"path": "main/dpdk.c", "line": 666, "comment": "Reset to NULL to avoid double-free."}}]

Here is the diff to review:

```diff
{diff}
```
"""

response = openai.chat.completions.create(
    model="o4-mini",
    messages=[
        {"role": "user", "content": prompt},
    ],
    temperature=0.2,
    max_tokens=800,
)

result = response.choices[0].message.content.strip()
result = result.removeprefix("```json")
result = result.removesuffix("```")
parsed = json.loads(result.strip())
for c in parsed:
    comments.append(
        {
            "path": c["path"],
            "line": c["line"],
            "body": c["comment"],
            "commit_id": COMMIT_ID,
        }
    )

if comments:
    for c in comments:
        print(f"adding comment on {c['path']}:{c['line']}: {c['body']}")
        r = requests.post(
            f"https://api.github.com/repos/{REPO}/pulls/{PR_NUMBER}/comments",
            headers={
                "Authorization": f"Bearer {GITHUB_TOKEN}",
                "Accept": "application/vnd.github+json",
            },
            json=c,
        )
        if r.status_code >= 300:
            print(
                "error: failed to post comment:", r.status_code, r.text, file=sys.stderr
            )
            os.exit(1)
else:
    print("no actionable review comments.")
