# syntax=docker/dockerfile:1.4
# Build stage - shared build environment
FROM --platform=$BUILDPLATFORM golang:1.25.6-alpine AS base
WORKDIR /src
RUN apk --no-cache add ca-certificates tzdata

# Deps stage - download and verify dependencies
FROM base AS deps
COPY . .
RUN go mod init cfgo-dyndns && go mod download

# Build stage - compile the application
FROM deps AS builder
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -buildvcs=false \
    -ldflags="-w -s" \
    -o /app/dyndns

# Final stage - minimal runtime
FROM scratch
COPY --from=base /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=base /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /app/dyndns /dyndns

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/dyndns", "-health-check"]
ENTRYPOINT ["/dyndns"]
