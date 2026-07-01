ARG INSTALL_CLAUDE_CODE=true
ARG INSTALL_CODEX=true
ARG INSTALL_GEMINI=true
ARG INSTALL_COPILOT=true
ARG INSTALL_OPENCODE=true
ARG INSTALL_DROID=true
ARG INSTALL_HAPI=true
ARG INSTALL_CLOUDFLARED=true
ARG INSTALL_CHISEL=true
ARG INSTALL_AO=true

FROM debian:bookworm-slim AS runtime-base

# Install Node.js 22.x directly from Node.js official binary
RUN NODE_VERSION="22.14.0" && \
    ARCH="$(uname -m)" && \
    if [ "$ARCH" = "aarch64" ]; then \
      NODE_ARCH="arm64"; \
    elif [ "$ARCH" = "x86_64" ]; then \
      NODE_ARCH="x64"; \
    else \
      echo "Unsupported architecture: $ARCH"; \
      exit 1; \
    fi && \
    apt-get update && \
    apt-get install -y --no-install-recommends bubblewrap ca-certificates curl gh git openssh-server python3-pip python3-venv rsync tini tmux util-linux xz-utils && \
    curl -fsSLO "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-${NODE_ARCH}.tar.xz" && \
    tar -xJf "node-v${NODE_VERSION}-linux-${NODE_ARCH}.tar.xz" -C /usr/local --strip-components=1 --no-same-owner && \
    rm "node-v${NODE_VERSION}-linux-${NODE_ARCH}.tar.xz" && \
    ln -sf /usr/local/bin/node /usr/local/bin/nodejs && \
    rm -rf /var/lib/apt/lists/*

# Install and configure UTF-8 locale
RUN apt-get update && \
    apt-get install -y --no-install-recommends locales && \
    echo "en_US.UTF-8 UTF-8" > /etc/locale.gen && \
    locale-gen en_US.UTF-8 && \
    echo "LANG=en_US.UTF-8" > /etc/default/locale && \
    rm -rf /var/lib/apt/lists/*

# Set UTF-8 environment for all processes
ENV LANG=en_US.UTF-8 \
    LANGUAGE=en_US:en \
    LC_ALL=en_US.UTF-8 \
    LC_CTYPE=en_US.UTF-8 \
    CLAUDE_CONFIG_DIR=/home/hapi/.claude

# Invalidate layer when npm itself has a new release
ADD https://registry.npmjs.org/npm/latest /tmp/npm-latest.json
# Update npm to latest version with retry
RUN for i in 1 2 3 4 5; do npm install -g npm@latest && break || sleep 10; done && \
    rm -f /tmp/npm-latest.json

# Install TTYD (multi-architecture support)
RUN TTYD_VERSION="1.7.7" && \
    TTYD_ARCH="$(dpkg --print-architecture | sed -e 's/armhf/arm/' -e 's/amd64/x86_64/')" && \
    if [ "$TTYD_ARCH" = "arm64" ]; then TTYD_ARCH="aarch64"; fi && \
    echo "Installing ttyd for architecture: $TTYD_ARCH" && \
    curl -fsSL "https://github.com/tsl0922/ttyd/releases/download/${TTYD_VERSION}/ttyd.${TTYD_ARCH}" \
    -o /usr/local/bin/ttyd && \
    chmod +x /usr/local/bin/ttyd

# Install SSH-tunnel providers (issue #79): cloudflared (default) + chisel.
# Both expose the container's sshd (port 22) externally where port forwarding is
# unavailable (Railway/PaaS). Both are Go with prebuilt linux amd64+arm64 binaries,
# so they install via curl on both arches (like ttyd) — NO Go build-stage needed
# (that is only for `ao`, issue #77). Each is gated by INSTALL_<KEY> (issue #57)
# with a strict true|false case (fail-closed on anything else, like Hermes).
# (Re-declared here because ARGs are scoped per build stage; the top-of-file
# copies do not carry into this runtime-base RUN.)
ARG INSTALL_CLOUDFLARED=true
ARG INSTALL_CHISEL=true
RUN TUNNEL_ARCH="$(dpkg --print-architecture)" && \
    case "${INSTALL_CLOUDFLARED}" in \
      false) echo "Skipping cloudflared (INSTALL_CLOUDFLARED=false)" ;; \
      true) \
        CLOUDFLARED_VERSION="2026.6.1" && \
        echo "Installing cloudflared ${CLOUDFLARED_VERSION} for ${TUNNEL_ARCH}" && \
        curl -fsSL "https://github.com/cloudflare/cloudflared/releases/download/${CLOUDFLARED_VERSION}/cloudflared-linux-${TUNNEL_ARCH}" \
          -o /usr/local/bin/cloudflared && \
        chmod +x /usr/local/bin/cloudflared ;; \
      *) echo "ERROR: INSTALL_CLOUDFLARED='${INSTALL_CLOUDFLARED}' is invalid; must be 'true' or 'false'" >&2; exit 1 ;; \
    esac && \
    case "${INSTALL_CHISEL}" in \
      false) echo "Skipping chisel (INSTALL_CHISEL=false)" ;; \
      true) \
        CHISEL_VERSION="1.11.5" && \
        echo "Installing chisel ${CHISEL_VERSION} for ${TUNNEL_ARCH}" && \
        curl -fsSL "https://github.com/jpillora/chisel/releases/download/v${CHISEL_VERSION}/chisel_${CHISEL_VERSION}_linux_${TUNNEL_ARCH}.gz" \
          -o /tmp/chisel.gz && \
        gunzip -c /tmp/chisel.gz > /usr/local/bin/chisel && \
        rm -f /tmp/chisel.gz && \
        chmod +x /usr/local/bin/chisel ;; \
      *) echo "ERROR: INSTALL_CHISEL='${INSTALL_CHISEL}' is invalid; must be 'true' or 'false'" >&2; exit 1 ;; \
    esac

# Invalidate cache when npm package versions change (used by build.sh for local builds)
ARG NPM_VERSIONS_HASH=default

# Create user and group for running hapi
RUN groupadd -r hapi && useradd -r -g hapi -s /bin/bash hapi && mkdir -p /home/hapi && chown -R hapi:hapi /home/hapi
RUN echo 'export TERM=xterm-256color' >> /home/hapi/.bashrc && \
    echo 'export LANG=en_US.UTF-8' >> /home/hapi/.bashrc && \
    echo 'export LC_ALL=en_US.UTF-8' >> /home/hapi/.bashrc

# Per-tool npm manifest stages (issue #57). For each tool a selector stage
# resolves to either its remote manifest ADD (enabled → cache-busts on a new
# published version) or the stable disabled placeholder below (disabled → never
# fetches, never invalidates the shared install layer). Keep in sync with
# cli-packages.txt.
FROM scratch AS npm-manifest-disabled
# Stable, constant placeholder (NOT cli-packages.txt): editing a disabled tool's
# row must not change this stage's output, or it would invalidate the shared
# install layer for the enabled tools.
COPY bin/npm-manifest-placeholder.json /manifest.json

FROM scratch AS npm-manifest-claude-code-true
ADD https://registry.npmjs.org/@anthropic-ai/claude-code/latest /manifest.json
FROM npm-manifest-disabled AS npm-manifest-claude-code-false
FROM npm-manifest-claude-code-${INSTALL_CLAUDE_CODE} AS npm-manifest-claude-code

FROM scratch AS npm-manifest-codex-true
ADD https://registry.npmjs.org/@openai/codex/latest /manifest.json
FROM npm-manifest-disabled AS npm-manifest-codex-false
FROM npm-manifest-codex-${INSTALL_CODEX} AS npm-manifest-codex

FROM scratch AS npm-manifest-gemini-true
ADD https://registry.npmjs.org/@google/gemini-cli/latest /manifest.json
FROM npm-manifest-disabled AS npm-manifest-gemini-false
FROM npm-manifest-gemini-${INSTALL_GEMINI} AS npm-manifest-gemini

FROM scratch AS npm-manifest-copilot-true
ADD https://registry.npmjs.org/@github/copilot/latest /manifest.json
FROM npm-manifest-disabled AS npm-manifest-copilot-false
FROM npm-manifest-copilot-${INSTALL_COPILOT} AS npm-manifest-copilot

FROM scratch AS npm-manifest-opencode-true
ADD https://registry.npmjs.org/opencode-ai/latest /manifest.json
FROM npm-manifest-disabled AS npm-manifest-opencode-false
FROM npm-manifest-opencode-${INSTALL_OPENCODE} AS npm-manifest-opencode

FROM scratch AS npm-manifest-droid-true
ADD https://registry.npmjs.org/droid/latest /manifest.json
FROM npm-manifest-disabled AS npm-manifest-droid-false
FROM npm-manifest-droid-${INSTALL_DROID} AS npm-manifest-droid

FROM scratch AS npm-manifest-hapi-true
ADD https://registry.npmjs.org/@twsxtd/hapi/latest /manifest.json
FROM npm-manifest-disabled AS npm-manifest-hapi-false
FROM npm-manifest-hapi-${INSTALL_HAPI} AS npm-manifest-hapi

# ao (agent-orchestrator) — Go binary built from source (issue #76/#77).
# Not a prebuilt download and not an npm package: ao is a Go program whose only
# native dep is the pure-Go modernc.org/sqlite driver, so CGO_ENABLED=0 yields one
# static build path for every architecture — no arch branches, no gcc/musl. GOARCH
# is resolved from buildx's TARGETARCH when set, else from the host's
# `dpkg --print-architecture` (matching the ttyd/tunnel steps above): TARGETARCH is
# a BuildKit-only automatic arg, so a non-BuildKit native build leaves it empty —
# defaulting to amd64 there would silently produce an amd64 binary inside an arm64
# image (green build, runtime failure). INSTALL_AO selects the real build stage or
# an empty placeholder via a FROM alias, mirroring the npm-manifest-* gating above;
# when disabled, BuildKit never schedules the golang stage at all (no toolchain).
#
# Source pinning: the Go `backend/` rewrite is NOT yet in any upstream release tag
# (those tags are still the old TypeScript monorepo, no backend/). The Go tree only
# exists on the moving upstream main and on the fork branch, so we pin AO_REF to a
# specific fork commit for a reproducible build. AO_REPO/AO_REF are overridable via
# --build-arg to retarget upstream once a Go-bearing tag is published.
# AO_REF lives inside the stage (not as a global pre-FROM ARG): it isn't used in any
# FROM line, so a global default wouldn't reach this RUN, and a bare in-stage `ARG
# AO_REF` would reset it to empty. A full commit SHA can't be used with `clone
# --branch`, so we clone shallow + fetch the exact SHA + checkout.
FROM golang:1.25-bookworm AS ao-build-true
ARG AO_REPO=https://github.com/axisrow/agent-orchestrator.git
ARG AO_REF=405be363fbe414dd93a81b12dfcfea112e277741
ARG TARGETARCH
RUN git init -q /src && \
    cd /src && \
    git remote add origin "${AO_REPO}" && \
    git fetch --depth 1 origin "${AO_REF}" && \
    git checkout -q FETCH_HEAD && \
    cd /src/backend && \
    GOARCH="${TARGETARCH:-$(dpkg --print-architecture)}" && \
    echo "Building ao for GOARCH=${GOARCH}" && \
    CGO_ENABLED=0 GOOS=linux GOARCH="${GOARCH}" \
      go build -trimpath -ldflags='-s -w' -o /out/ao ./cmd/ao

# Disabled placeholder: produce an empty /out/ao so the final COPY has a source,
# without cloning or compiling anything. The final stage drops it (see below).
FROM busybox AS ao-build-false
RUN mkdir -p /out && : > /out/ao

FROM ao-build-${INSTALL_AO} AS ao-build

FROM runtime-base

# Modular install flags (issue #57): set any to "false" at build time to drop
# that CLI tool from the image, e.g. `docker build --build-arg INSTALL_CODEX=false`.
# Defaults are "true", so an unspecified build installs everything (unchanged).
# Keep the keys in sync with cli-packages.txt and .env.example.
ARG INSTALL_CLAUDE_CODE=true
ARG INSTALL_CODEX=true
ARG INSTALL_GEMINI=true
ARG INSTALL_COPILOT=true
ARG INSTALL_OPENCODE=true
ARG INSTALL_DROID=true
ARG INSTALL_HAPI=true
ARG INSTALL_AO=true
ARG INSTALL_HERMES=true
ARG INSTALL_CLOUDFLARED=true
ARG INSTALL_CHISEL=true

COPY --from=npm-manifest-claude-code /manifest.json /tmp/npm-manifests/claude-code.json
COPY --from=npm-manifest-codex /manifest.json /tmp/npm-manifests/codex.json
COPY --from=npm-manifest-gemini /manifest.json /tmp/npm-manifests/gemini-cli.json
COPY --from=npm-manifest-copilot /manifest.json /tmp/npm-manifests/copilot.json
COPY --from=npm-manifest-opencode /manifest.json /tmp/npm-manifests/opencode-ai.json
COPY --from=npm-manifest-droid /manifest.json /tmp/npm-manifests/droid.json
COPY --from=npm-manifest-hapi /manifest.json /tmp/npm-manifests/hapi.json

COPY cli-packages.txt /tmp/cli-packages.txt
COPY bin/install-cli.sh /tmp/install-cli.sh

# Install the enabled CLI tools in one layer, then fix permissions and clean up.
# install-cli.sh reads the INSTALL_<KEY> values from the environment, so promote
# the build args to env vars for the duration of this RUN.
RUN chmod +x /tmp/install-cli.sh && \
    INSTALL_CLAUDE_CODE="${INSTALL_CLAUDE_CODE}" \
    INSTALL_CODEX="${INSTALL_CODEX}" \
    INSTALL_GEMINI="${INSTALL_GEMINI}" \
    INSTALL_COPILOT="${INSTALL_COPILOT}" \
    INSTALL_OPENCODE="${INSTALL_OPENCODE}" \
    INSTALL_DROID="${INSTALL_DROID}" \
    INSTALL_HAPI="${INSTALL_HAPI}" \
    /tmp/install-cli.sh /tmp/cli-packages.txt && \
    chown -R hapi:hapi /usr/local/lib/node_modules && \
    npm cache clean --force && \
    rm -rf /tmp/*

# Install Hermes Agent (Nous Research) — git clone + pip, no venv/uv.
# Gated by INSTALL_HERMES so it can be dropped from lighter images (issue #57).
# Strict boolean: only true/false accepted; fail closed on anything else (e.g.
# "False", "0") so a misconfigured build never silently ships Hermes.
RUN case "${INSTALL_HERMES}" in \
      false) \
        echo "Skipping Hermes Agent (INSTALL_HERMES=false)" ;; \
      true) \
        git clone --depth 1 https://github.com/NousResearch/hermes-agent.git /tmp/hermes-agent && \
        cd /tmp/hermes-agent && \
        pip install --break-system-packages '.[all,messaging]' && \
        which hermes && \
        rm -rf /tmp/hermes-agent ;; \
      *) \
        echo "ERROR: INSTALL_HERMES='${INSTALL_HERMES}' is invalid; must be 'true' or 'false'" >&2; \
        exit 1 ;; \
    esac

# Install the ao binary built in the ao-build stage above (issue #76/#77). The
# disabled stage produced an empty placeholder, so when INSTALL_AO=false we drop
# it instead of shipping a bogus executable. Strict true|false (fail closed). The
# binary is not run here — on a cross-built (foreign-arch) image it can't execute.
COPY --from=ao-build /out/ao /tmp/ao.bin
RUN case "${INSTALL_AO}" in \
      true) \
        install -m 0755 /tmp/ao.bin /usr/local/bin/ao ;; \
      false) \
        echo "Skipping ao (INSTALL_AO=false)" ;; \
      *) \
        echo "ERROR: INSTALL_AO='${INSTALL_AO}' is invalid; must be 'true' or 'false'" >&2; \
        exit 1 ;; \
    esac && \
    rm -f /tmp/ao.bin

# Create app directory for TTYD proxy
RUN mkdir -p /app /bin

COPY app/ /app/
COPY bin/tmux-wrapper.sh /bin/tmux-wrapper.sh
COPY bin/glm /bin/glm
COPY bin/claude-auth-snapshot.sh /bin/claude-auth-snapshot.sh
COPY config/.tmux.conf /home/hapi/.tmux.conf
COPY config/.tmux.conf /etc/skel/.tmux.conf
RUN mkdir -p /etc/skel/.claude
COPY config/claude-settings.json /etc/skel/.claude/settings.json
RUN chmod +x /bin/tmux-wrapper.sh /bin/glm /bin/claude-auth-snapshot.sh && \
    chown hapi:hapi /home/hapi/.tmux.conf

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8080

# tini as PID 1 reaps zombies (orphaned subshells) and forwards signals.
# -g forwards SIGTERM to the whole process group so the ttyd proxy / hapi server
# / droid daemon (reparented to tini after entrypoint.sh exec's sshd) shut down
# gracefully on `docker stop` instead of being SIGKILLed after the grace period (B13).
ENTRYPOINT ["/usr/bin/tini", "-g", "--", "/entrypoint.sh"]
CMD ["/usr/sbin/sshd", "-D", "-e"]
