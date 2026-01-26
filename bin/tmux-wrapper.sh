#!/bin/bash
# tmux-wrapper.sh - Присоединяется к существующей tmux сессии или создаёт новую
# Обеспечивает постоянные сессии при переподключении к терминалу

# Ensure UTF-8 encoding
export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8
export LC_CTYPE=en_US.UTF-8

SESSION_NAME="ttyd-$(whoami)"

if tmux has-session -t "$SESSION_NAME" 2>/dev/null; then
    exec tmux attach-session -t "$SESSION_NAME"
else
    exec tmux new-session -s "$SESSION_NAME" -c "$HOME"
fi
