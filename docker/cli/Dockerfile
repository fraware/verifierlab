# syntax=docker/dockerfile:1.7
# VerifierLab CLI image — validate / orchestrate / report / release utilities.
# Must not ship hidden-label key material or adjudicator secrets.
#
# Base pin: python:3.12-slim-bookworm (digest refreshed periodically).

ARG PYTHON_BASE=python:3.12-slim-bookworm@sha256:a116514e19457bcb7af7efe9c3dd0b9b71e85b317694e7882a1c52aa15a78134

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
LABEL org.opencontainers.image.title="verifierlab-cli" \
      org.opencontainers.image.description="VerifierLab CLI (validate/orchestrate/report)" \
      org.opencontainers.image.source="https://github.com/fraware/verifierlab" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="fraware" \
      io.verifierlab.role="cli" \
      io.verifierlab.trust-boundary="cli"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    VALAB_ROLE=cli \
    VALAB_DATA=/var/lib/verifierlab/cli

RUN groupadd --system --gid 10001 valab \
    && useradd --system --uid 10001 --gid valab --home-dir /home/valab --create-home valab \
    && mkdir -p /var/lib/verifierlab/cli \
    && chown -R valab:valab /var/lib/verifierlab

COPY --from=build /usr/local /usr/local
COPY docker/cli/entrypoint.py /usr/local/bin/valab-role-entrypoint
RUN chmod 755 /usr/local/bin/valab-role-entrypoint

USER 10001:10001
WORKDIR /work
ENTRYPOINT ["valab-role-entrypoint"]
CMD ["--help"]
