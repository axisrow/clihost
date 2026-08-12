# Container service lifecycle contract

`entrypoint.sh` bootstraps several processes, but it is **not a supervisor**.
This document records the lifecycle contract implemented for issue #112. Adding
restarts, PID 1 reaping, or making a background process control container
health requires a separate design and issue.

## Service matrix

| Service | Enabled / required | Startup failure | Startup check | Failure after startup |
| --- | --- | --- | --- | --- |
| `sshd` | Always required | `exec` fails and the container exits | OpenSSH owns its own initialization | Exits the container because it is PID 1 |
| `ttyd_proxy.py` | Always started; required for web access, not for container lifetime | Invalid shell-owned config fails fast before launch. An immediate child exit after launch fails the container (`exit 1`) — it is the only service with fail-closed startup, since it is the container's sole HTTP service and there is no supervisor to notice a silent death later | PID liveness after the initial exec window, checked directly (not via `start_background_service`) | Not monitored or restarted; container remains alive while `sshd` lives |
| `droid daemon --remote-access` | Optional (`DROID_DAEMON_ENABLED=true`) | Invalid name or failed registration fails fast. Missing binary or immediate daemon exit warns and skips | PID liveness after the initial exec window | Not monitored or restarted |
| `ao daemon` | Optional (`AO_DAEMON_ENABLED=true`) | Invalid port fails fast. Missing binary or immediate daemon exit warns and skips | PID liveness after the initial exec window | Not monitored or restarted |
| SSH tunnel (`cloudflared` / `chisel`) | Optional (`SSH_TUNNEL_ENABLED=true`) | Invalid provider/port fails fast. Missing binary/config or immediate client exit warns and skips | PID liveness after the initial exec window | Not monitored or restarted |
| `hapi server --relay` | Started when the `hapi` binary exists | Missing binary or immediate server exit warns and skips | PID liveness after the initial exec window; relay URL creation is best-effort | Not monitored or restarted |
| `hapi runner` | Optional (`HAPI_RUNNER_ENABLED=true`) and requires `hapi` | Start/status failure warns and continues; `hapi doctor` supplies diagnostics | One `hapi runner status` readiness check | Not monitored or restarted by `entrypoint.sh` |

`ttyd` and tmux session processes are outside this matrix because
`ttydproxy.manager` owns their per-session lifecycle rather than the container
entrypoint.

## Shared startup behavior

Long-lived background commands started directly by the entrypoint go through
`start_background_service`. It launches the exact argv, preserves the existing
log destination, records the PID, waits only for a short exec window, and warns
if the process has already exited. This is a startup liveness check only:
there is deliberately no polling loop, signal handler, or restart policy.

`ttyd_proxy.py` is the one exception: it uses its own inline PID-capture +
`kill -0` check (predating this shared helper, from issue #113) that **exits
the container** on an immediate death instead of warning and continuing. It is
the container's only HTTP service, so a silent post-launch death (e.g. a
malformed Python-owned env var the shell-side contract doesn't validate) must
not leave the container "healthy" (sshd still up) with no way to serve
terminals.

Readiness is checked only where the CLI already exposes a stable probe. Today
that is `hapi runner status`, called through `check_service_readiness`. PID
existence is not treated as functional readiness for the other services.
