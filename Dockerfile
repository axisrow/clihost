FROM debian:bookworm-slim

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
    apt-get install -y --no-install-recommends ca-certificates curl gh git openssh-server python3-pip python3-venv tmux util-linux vim nano xz-utils && \
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

# Update npm to latest version with retry
RUN for i in 1 2 3 4 5; do npm install -g npm@latest && break || sleep 10; done

# Install TTYD (multi-architecture support)
RUN TTYD_VERSION="1.7.7" && \
    TTYD_ARCH="$(dpkg --print-architecture | sed -e 's/armhf/arm/' -e 's/amd64/x86_64/')" && \
    if [ "$TTYD_ARCH" = "arm64" ]; then TTYD_ARCH="aarch64"; fi && \
    echo "Installing ttyd for architecture: $TTYD_ARCH" && \
    curl -fsSL "https://github.com/tsl0922/ttyd/releases/download/${TTYD_VERSION}/ttyd.${TTYD_ARCH}" \
    -o /usr/local/bin/ttyd && \
    chmod +x /usr/local/bin/ttyd

# Invalidate cache when npm package versions change
ARG NPM_VERSIONS_HASH=default

# Install Claude Code via npm with retry
RUN for i in 1 2 3 4 5; do npm install -g @anthropic-ai/claude-code@latest && break || sleep 10; done

# Install OpenAI Codex CLI (global via npm) with retry
RUN for i in 1 2 3 4 5; do npm install -g @openai/codex@latest && break || sleep 10; done

# Install Google Gemini CLI (global via npm) with retry
RUN for i in 1 2 3 4 5; do npm install -g @google/gemini-cli@latest && break || sleep 10; done

# Create user and group for running hapi
RUN groupadd -r hapi && useradd -r -g hapi -s /bin/bash hapi && mkdir -p /home/hapi && chown -R hapi:hapi /home/hapi
RUN echo 'export TERM=xterm-256color' >> /home/hapi/.bashrc && \
    echo 'export LANG=en_US.UTF-8' >> /home/hapi/.bashrc && \
    echo 'export LC_ALL=en_US.UTF-8' >> /home/hapi/.bashrc

# Install hapi CLI (global via npm) https://github.com/tiann/hapi
RUN npm install -g @twsxtd/hapi@latest && chown -R hapi:hapi /usr/local/lib/node_modules

# Create app directory for TTYD proxy
RUN mkdir -p /app /bin

COPY app/ /app/
COPY bin/tmux-wrapper.sh /bin/tmux-wrapper.sh
COPY bin/glm /bin/glm
RUN chmod +x /bin/tmux-wrapper.sh /bin/glm

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8080

ENTRYPOINT ["/entrypoint.sh"]
CMD ["/usr/sbin/sshd", "-D", "-e"]
