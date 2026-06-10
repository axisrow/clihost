#!/bin/bash
# tmux-wrapper.sh - Присоединяется к существующей tmux сессии или создаёт новую
# Обеспечивает постоянные сессии при переподключении к терминалу

# Ensure UTF-8 encoding
export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8
export LC_CTYPE=en_US.UTF-8

SESSION_NAME="${1:-ttyd-$(whoami)}"

# -A attaches when the session already exists; the tmux server serializes
# session creation, so simultaneous clients cannot race each other.
exec tmux new-session -A -s "$SESSION_NAME" -c "$HOME"
