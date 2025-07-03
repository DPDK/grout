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
GITHUB_BASE_URL = f"https://api.github.com/repos/{REPO}"
GITHUB_AUTH = {
    "Authorization": f"Bearer {GITHUB_TOKEN}",
}
PROMPT = """You are an expert C developer reviewing a GitHub pull request.

Focus on:
- Memory safety (e.g., buffer overflows, pointer misuse)
- Correctness (null checks, type safety, missing error handling)
- Code clarity and clean style
- Use of standard idioms and conventions (C23)

Only provide helpful, relevant comments.
Be brief and terse but clear.
Only include issues worth commenting.
Never suggest to add code comments.

You will be provided the full pull request diff and a list of updated file contents.
The review comments should only refer to changed lines in the diff.
Make sure you are accurate about the line numbers in the file.

Provide a list of concise per-file line comments in JSON format. Example:

```json
{
  "comments": [
    {
      "path": "modules/infra/cli/nexthop.c",
      "line": 42,
      "body": "Return value of malloc is not checked."
    },
    {
      "path": "main/dpdk.c",
      "line": 666,
      "body": "Reset to NULL to avoid double-free.",
    }
  ]
}
```
"""


def github_get(url: str) -> dict:
    url = f"{GITHUB_BASE_URL}/{url}"
    print(f"fetching json {url}")
    return requests.get(url, headers=GITHUB_AUTH).json()


def github_get_raw(commit: str, filename: str) -> str:
    url = f"https://github.com/{REPO}/raw/{commit}/{filename}"
    print(f"fetching raw {url}")
    return requests.get(url).text


def github_get_diff() -> str:
    url = f"https://github.com/{REPO}/pull/{PR_NUMBER}.diff"
    print(f"fetching diff {url}")
    return requests.get(url).text


def github_post(url: str, data: dict) -> requests.Response:
    url = f"{GITHUB_BASE_URL}/{url}"
    print(f"posting json {url}")
    return requests.post(url, json=data, headers=GITHUB_AUTH)


def main():
    pr_info = github_get(f"pulls/{PR_NUMBER}")
    diff = github_get_diff()
    commit = pr_info["head"]["sha"]

    request = f"""Here is the diff:

```diff
{diff}
```

And here are the files:
"""

    files = {}
    for file in github_get(f"pulls/{PR_NUMBER}/files"):
        if file["status"] not in ("added", "modified"):
            continue
        name = file["filename"]
        files[name] = github_get_raw(commit, name)
        request += f"""

========================= {name} ===========================

```
{files[name]}
```
"""

    client = openai.OpenAI()
    response = client.responses.parse(
        model="o4-mini",
        input=[
            {"role": "developer", "content": PROMPT},
            {"role": "user", "content": request},
        ],
        text={
            "format": {
                "type": "json_schema",
                "name": "review",
                "schema": {
                    "type": "object",
                    "properties": {
                        "comments": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "path": {"type": "string"},
                                    "line": {"type": "number"},
                                    "body": {"type": "string"},
                                },
                                "required": ["path", "line", "body"],
                                "additionalProperties": False,
                            },
                        },
                    },
                    "required": ["comments"],
                    "additionalProperties": False,
                },
                "strict": True,
            }
        },
    )
    try:
        for c in json.loads(response.output_text.strip())["comments"]:
            file = files[c["path"]]
            lines = file.splitlines()
            start_line = max(c["line"], 1)
            line = min(c["line"] + 5, len(lines))
            comment = {
                "path": c["path"],
                "start_line": start_line,
                "line": line,
                "side": "RIGHT",
                "body": c["body"],
                "commit_id": commit,
            }
            print(f"review {c['path']}:{c['line']}: {c['body']}")
            r = github_post(f"pulls/{PR_NUMBER}/comments", comment)
            if r.status_code >= 300:
                print(
                    f"error: failed to post comment: {r.status_code} {r.text}",
                    file=sys.stderr,
                )
    except (json.JSONDecodeError, KeyError) as e:
        print(f"error: failed to parse AI response: {e}", file=sys.stderr)
        print(response.output_text)


if __name__ == "__main__":
    main()
