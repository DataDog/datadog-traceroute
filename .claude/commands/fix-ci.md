---
description: Check GitHub CI status, wait if running, fix failures and push
argument-hint: [branch-name]
allowed-tools: mcp__github__*, Bash(git:*), Bash(gh:*), Read, Edit, Write, Grep, Glob
---

## Task

Monitor and fix GitHub CI checks for the PR branch.

## Context

- Target branch: $ARGUMENTS (use current branch if not specified)

## Instructions

1. **Run Local Tests First** (faster feedback):
   - Run tests locally
   - If tests fail locally:
     - Analyze the root cause
     - Fix the issues in the code
     - Re-run local tests to verify the fix
     - Commit the fix with a clear message
     - Push the changes
   - If tests pass locally, proceed to step 2

2. **Check CI Status**: Use the GitHub MCP tools

3. **If CI is still running**:
   - Wait 30-60 seconds
   - Check again
   - Repeat until all checks complete

4. **If CI checks pass**: Report success and stop.

5. **If CI checks fail**:
   - Identify which checks failed
   - Fetch the failure logs/details
   - Analyze the root cause
   - Fix the issues in the code
   - Commit the fix with a clear message
   - Push the changes
   - Go back to step 1 to verify the fix (run local tests first)

## Important

- Always explain what failed and why before attempting fixes
- Make minimal, targeted fixes - don't refactor unrelated code
- If you cannot determine the fix, ask for help instead of guessing
