# syntax=docker/dockerfile:1.7
# PARTIAL QUALIFICATION — RLlib integration conformance image.
# Not a capability / SOTA claim. Do not publish as fully release-qualified
# until Milestone C/D release gate completes end-to-end image smoke.

ARG PYTHON_BASE=python:3.12-slim-bookworm@sha256:a116514e19457bcb7af7efe9c3dd0b9b71e85b317694e7882a1c52aa15a78134

FROM ${PYTHON_BASE}
LABEL org.opencontainers.image.title="verifierlab-rllib" \
      org.opencontainers.image.description="VerifierLab RLlib image (partial qualification / integration conformance)" \
      org.opencontainers.image.source="https://github.com/fraware/verifierlab" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="fraware" \
      io.verifierlab.role="rllib" \
      io.verifierlab.trust-boundary="rllib" \
      io.verifierlab.qualification="partial-qualification" \
      io.verifierlab.claim="integration_conformance"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    VALAB_ROLE=rllib \
    VALAB_DATA=/var/lib/verifierlab/rllib \
    RAY_DISABLE_DOCKER_CPU_WARNING=1

RUN groupadd --system --gid 10001 valab \
    && useradd --system --uid 10001 --gid valab --home-dir /home/valab --create-home valab \
    && mkdir -p /var/lib/verifierlab/rllib \
    && chown -R valab:valab /var/lib/verifierlab \
    && apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

# Pin matches pyproject [rllib] extra. Image remains partial-qualification.
COPY pyproject.toml README.md LICENSE /src/
COPY src /src/src
RUN pip install --no-cache-dir "/src[rllib]" \
    && printf '%s\n' \
      '#!/bin/sh' \
      'echo "verifierlab-rllib partial qualification (integration conformance, not capability)."' \
      'python -c "from verifierlab.trainers.rllib_adapter import ray_rllib_available; import sys; sys.exit(0 if ray_rllib_available() else 2)"' \
      > /usr/local/bin/valab-rllib-smoke \
    && chmod 755 /usr/local/bin/valab-rllib-smoke

USER 10001:10001
WORKDIR /work
ENTRYPOINT ["valab-rllib-smoke"]
