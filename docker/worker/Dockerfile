# syntax=docker/dockerfile:1.7
# VerifierLab worker image — environments, attacks, broker client.
# Must not contain GT providers, vault material, or adjudicator credentials.

ARG PYTHON_BASE=python:3.12-slim-bookworm@sha256:60b63e1aa22af2bd734a72e4acc572c1dde035250cc9da5d16a0bdcff2fba82f

FROM ${PYTHON_BASE} AS build
WORKDIR /src
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY pyproject.toml README.md LICENSE CHANGELOG.md ./
COPY src ./src
COPY campaigns ./campaigns
COPY scripts ./scripts
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir .

FROM ${PYTHON_BASE}
LABEL org.opencontainers.image.title="verifierlab-worker" \
      org.opencontainers.image.description="VerifierLab attack worker (no vault / GT)" \
      org.opencontainers.image.source="https://github.com/fraware/verifierlab" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="fraware" \
      io.verifierlab.role="worker" \
      io.verifierlab.trust-boundary="worker"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    VALAB_ROLE=worker \
    VALAB_DATA=/var/lib/verifierlab/worker

RUN groupadd --system --gid 10001 valab \
    && useradd --system --uid 10001 --gid valab --home-dir /home/valab --create-home valab \
    && mkdir -p /var/lib/verifierlab/worker \
    && chown -R valab:valab /var/lib/verifierlab

COPY --from=build /usr/local /usr/local
COPY docker/worker/entrypoint.py /usr/local/bin/valab-role-entrypoint
RUN chmod 755 /usr/local/bin/valab-role-entrypoint

USER 10001:10001
WORKDIR /work
ENTRYPOINT ["valab-role-entrypoint"]
CMD ["campaign", "run", "--help"]
