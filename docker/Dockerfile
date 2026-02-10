FROM debian:bookworm-slim

LABEL maintainer="bitsadmin - https://github.com/bitsadmin/lofl"
LABEL description="LOFL - Living Off the Foreign Land"

# Install system packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    dnsmasq \
    python3 \
    python3-dnslib \
    python3-yaml \
    socat \
    iptables \
    iproute2 \
    dnsutils \
    supervisor \
    curl \
    ca-certificates \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Download tun2socks
ARG TUN2SOCKS_VERSION=v2.6.0
ARG TARGETARCH
RUN case "${TARGETARCH}" in \
        amd64) ARCH="amd64" ;; \
        arm64) ARCH="arm64" ;; \
        *) echo "Unsupported architecture: ${TARGETARCH}" && exit 1 ;; \
    esac && \
    curl -L -o /tmp/tun2socks.zip \
    "https://github.com/xjasonlyu/tun2socks/releases/download/${TUN2SOCKS_VERSION}/tun2socks-linux-${ARCH}.zip" && \
    unzip /tmp/tun2socks.zip -d /tmp && \
    mv /tmp/tun2socks-linux-${ARCH} /usr/local/bin/tun2socks && \
    chmod +x /usr/local/bin/tun2socks && \
    rm -f /tmp/tun2socks.zip

# Create directories
RUN mkdir -p /opt/lofl /etc/lofl /var/log/supervisor

# Copy LOFL scripts
COPY dns_over_tcp.py /opt/lofl/
COPY cldaproxy.sh /opt/lofl/
COPY create_tun.sh /opt/lofl/
COPY iptables_nat.sh /opt/lofl/
COPY add_routes.sh /opt/lofl/
RUN chmod +x /opt/lofl/*.sh

# Copy docker-specific files
COPY docker/supervisord.conf /etc/supervisor/supervisord.conf
COPY docker/entrypoint.py /opt/lofl/entrypoint.py
RUN chmod +x /opt/lofl/entrypoint.py

# Supervisor socket for supervisorctl
RUN mkdir -p /var/run/supervisor

ENTRYPOINT ["python3", "/opt/lofl/entrypoint.py"]
