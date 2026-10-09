FROM --platform=$BUILDPLATFORM golang:1.27.1-bookworm AS go
FROM --platform=$BUILDPLATFORM rust:1.99.0-bookworm AS build
COPY --from=go /usr/local/go /usr/local/go
ENV PATH="/usr/local/go/bin:${PATH}"
RUN apt-get update && apt-get install -y --no-install-recommends \
    jq gcc-aarch64-linux-gnu gcc-x86-64-linux-gnu libc6-dev-arm64-cross libc6-dev-amd64-cross && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /src/reference-implementations/agt-go
COPY reference-implementations/agt-go/ ./
COPY reference-implementations/agt/policy/ ../agt/policy/
COPY reference-implementations/agt/mapping.yaml ../agt/mapping.yaml
ARG TARGETARCH
ARG EVALUATOR=agt
RUN case "${TARGETARCH}" in \
      amd64) compiler=x86_64-linux-gnu-gcc ;; \
      arm64) compiler=aarch64-linux-gnu-gcc ;; \
      *) exit 1 ;; \
    esac && \
    CC=${compiler} make build GOOS=linux GOARCH=${TARGETARCH} EVALUATOR=${EVALUATOR} OUTPUT_DIR=/out && \
    if [ "${EVALUATOR}" = agt ]; then cp .acs/agt/linux-${TARGETARCH}/bin/opa /out/opa; fi && \
    mkdir /data

FROM gcr.io/distroless/cc-debian13:nonroot
COPY --from=build --chown=65532:65532 /data/ /data/
WORKDIR /app
COPY --from=build /out/ ./
COPY reference-implementations/agt-go/guardian.yaml ./guardian.yaml
COPY reference-implementations/agt/policy/ ./deployment/policy/
COPY reference-implementations/agt/mapping.yaml ./deployment/mapping.yaml
ARG EVALUATOR=agt
ENV ACS__SERVER__HOST=0.0.0.0 \
    ACS__POLICY__EVALUATOR=${EVALUATOR} \
    ACS__POLICY__DEPLOYMENT_DIR=/app/deployment \
    ACS__POLICY__OPA_PATH=/app/opa \
    ACS__SECURITY__HMAC_SECRET_FILE=/run/secrets/acs-hmac \
    ACS__AUDIT__ENVELOPE_LOG=/data/envelopes.jsonl \
    ACS__AUDIT__EVENT_LOG=/data/events.jsonl
USER 65532:65532
EXPOSE 8787
ENTRYPOINT ["/app/acs-guardian", "--config", "/app/guardian.yaml"]
