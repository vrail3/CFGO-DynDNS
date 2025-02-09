# syntax=docker/dockerfile:1.4
# Build stage - shared build environment
FROM --platform=$BUILDPLATFORM golang:1.23.6-alpine AS base
WORKDIR /src

# Deps stage - download and verify dependencies
FROM base AS deps
COPY go.mod go.sum ./
RUN go mod download

# Build stage - compile the application
FROM deps AS builder
COPY . .
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -buildvcs=false \
    -ldflags="-w -s" \
    -o /app/dyndns

# UPX stage - compress the binary
FROM alpine:latest AS compressor
COPY --from=builder /app/dyndns /app/dyndns
RUN apk add --no-cache upx && \
    upx --best --lzma /app/dyndns

# Final stage - minimal runtime
FROM gcr.io/distroless/static:nonroot
COPY --from=compressor /app/dyndns /dyndns

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/dyndns", "-health-check"]
ENTRYPOINT ["/dyndns"]
