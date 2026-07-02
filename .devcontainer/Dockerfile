FROM mcr.microsoft.com/devcontainers/go:1.26-bookworm

RUN export DEBIAN_FRONTEND=noninteractive \
    && apt-get update --allow-releaseinfo-change \
    && apt-get install -y --no-install-recommends netcat-openbsd \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
