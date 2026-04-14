#!/bin/bash
# Task 13: Auto-capture dev session summaries
# Appends recent git activity to memory/dev_sessions.md on session end
MEMORY_DIR="$HOME/.claude/projects/-home-kali-Documents-Web3/memory"
SESSION_LOG="$MEMORY_DIR/dev_sessions.md"
DATE=$(date +"%Y-%m-%d %H:%M")

RECENT_COMMITS=$(cd /home/kali/Documents/Web3 && git log --oneline -5 --since="8 hours ago" 2>/dev/null)
CHANGED_FILES=$(cd /home/kali/Documents/Web3 && git diff --name-only HEAD~3 2>/dev/null | head -15)

if [ -n "$RECENT_COMMITS" ] || [ -n "$CHANGED_FILES" ]; then
    {
        echo ""
        echo "## $DATE"
        [ -n "$RECENT_COMMITS" ] && echo "### Commits" && echo "$RECENT_COMMITS"
        [ -n "$CHANGED_FILES" ] && echo "### Files changed" && echo "$CHANGED_FILES"
        echo "---"
    } >> "$SESSION_LOG"
fi
