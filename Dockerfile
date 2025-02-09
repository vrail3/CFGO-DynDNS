# Build stage
FROM --platform=$BUILDPLATFORM golang:1.23.6-alpine AS builder

WORKDIR /src

# Copy and download dependencies first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build with proper cross-compilation settings
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
    -ldflags="-w -s" \
    -o /app/dyndns

# Final stage
FROM gcr.io/distroless/static:nonroot

COPY --from=builder /app/dyndns /dyndns

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/dyndns", "-health-check"]

ENTRYPOINT ["/dyndns"]
