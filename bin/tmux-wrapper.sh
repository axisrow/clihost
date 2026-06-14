#!/bin/bash
# tmux-wrapper.sh - Присоединяется к существующей tmux сессии или создаёт новую
# Обеспечивает постоянные сессии при переподключении к терминалу
#
# Когда TTYD_SANDBOX=true, tmux-сессия запускается внутри bubblewrap (bwrap)
# джейла: в мультитенантных деплоях (где каждый терминал запускается под своим
# Linux-юзером) пользователи не видят чужие /home/* и не могут писать в систему.
# По умолчанию (TTYD_SANDBOX не задан/false) поведение байт-в-байт как раньше.
#
# Требование для джейла: контейнер должен быть запущен с
#   --security-opt seccomp=unconfined
# иначе bwrap падает на создании namespace. Режим FAIL-CLOSED: если bwrap не
# стартует, терминал не открывается (отката к неизолированному терминалу нет).
# Очистка сессии (manager.py kill-session) при джейле становится no-op —
# жизненный цикл держит --die-with-parent; осиротевший tmux-сервер безвреден и
# переиспользуется при следующем переподключении (тот же сокет под $HOME).

# Ensure UTF-8 encoding
export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8
export LC_CTYPE=en_US.UTF-8

SESSION_NAME="${1:-ttyd-$(whoami)}"
: "${TTYD_SANDBOX:=false}"

if [ "${TTYD_SANDBOX}" = "true" ]; then
  # Per-jail /tmp — свежий tmpfs, поэтому дефолтный сокет tmux (/tmp/tmux-UID/
  # default) не переживает пере-запуск ttyd и `new-session -A` не находит старый
  # сервер. Кладём сокет под bind-примонтированный $HOME (тот же inode внутри и
  # снаружи джейла) — он переживает переподключения.
  TMUX_SOCK="${HOME}/.cache/tmux/clihost.sock"
  mkdir -p "${HOME}/.cache/tmux"

  # bwrap падает, если SOURCE у --ro-bind отсутствует ("Can't find source path"),
  # поэтому каждый системный путь биндим только если он существует.
  binds=()
  for p in /usr /bin /sbin /lib /lib64 /etc /usr/local; do
    [ -e "$p" ] && binds+=(--ro-bind "$p" "$p")
  done

  # Сеть НЕ изолируем (нет unshare сетевого namespace): AI CLI
  # (claude-code/codex/gemini) нужен доступ в интернет.
  # --unshare-user обязателен для непривилегированного запуска.
  # /proc наследуем read-only (свежий --proc не монтируется в части окружений):
  # файловая изоляция полная, скрытие чужих процессов — нет.
  exec bwrap \
    "${binds[@]}" \
    --ro-bind /proc /proc \
    --bind "$HOME" "$HOME" \
    --dev /dev --tmpfs /tmp --tmpfs /run \
    --unshare-user --unshare-pid --unshare-ipc \
    --die-with-parent \
    -- tmux -S "${TMUX_SOCK}" new-session -A -s "$SESSION_NAME" -c "$HOME"
fi

# -A attaches when the session already exists; the tmux server serializes
# session creation, so simultaneous clients cannot race each other.
exec tmux new-session -A -s "$SESSION_NAME" -c "$HOME"
