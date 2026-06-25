ARG INSTALL_CLAUDE_CODE=true
ARG INSTALL_CODEX=true
ARG INSTALL_GEMINI=true
ARG INSTALL_COPILOT=true
ARG INSTALL_OPENCODE=true
ARG INSTALL_DROID=true
ARG INSTALL_HAPI=true

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
    apt-get install -y --no-install-recommends bubblewrap ca-certificates curl gh git openssh-server python3-pip python3-venv tini tmux util-linux xz-utils && \
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

# Invalidate cache when npm package versions change (used by build.sh for local builds)
ARG NPM_VERSIONS_HASH=default

# Create user and group for running hapi
RUN groupadd -r hapi && useradd -r -g hapi -s /bin/bash hapi && mkdir -p /home/hapi && chown -R hapi:hapi /home/hapi
RUN echo 'export TERM=xterm-256color' >> /home/hapi/.bashrc && \
    echo 'export LANG=en_US.UTF-8' >> /home/hapi/.bashrc && \
    echo 'export LC_ALL=en_US.UTF-8' >> /home/hapi/.bashrc

# Invalidate the CLI install layer when enabled packages publish new versions.
# The selected manifest stages keep remote ADD cache-busting for enabled tools,
# while disabled tools copy a stable local file and never fetch their manifest.
# Keep in sync with cli-packages.txt.
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
ARG INSTALL_HERMES=true

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

# Create app directory for TTYD proxy
RUN mkdir -p /app /bin

COPY app/ /app/
COPY bin/tmux-wrapper.sh /bin/tmux-wrapper.sh
COPY bin/glm /bin/glm
COPY config/.tmux.conf /home/hapi/.tmux.conf
COPY config/.tmux.conf /etc/skel/.tmux.conf
RUN chmod +x /bin/tmux-wrapper.sh /bin/glm && \
    chown hapi:hapi /home/hapi/.tmux.conf

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8080

# tini as PID 1 reaps zombies (orphaned subshells) and forwards signals
ENTRYPOINT ["/usr/bin/tini", "--", "/entrypoint.sh"]
CMD ["/usr/sbin/sshd", "-D", "-e"]
