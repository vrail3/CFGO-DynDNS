# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /build

# Install necessary build tools and wget for healthcheck
RUN apk add --no-cache gcc musl-dev wget

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary with static linking
RUN CGO_ENABLED=0 go build -ldflags="-w -s" -o dyndns

# Production stage
FROM gcr.io/distroless/static:nonroot

# Copy the binary from builder
COPY --from=builder --chown=nonroot:nonroot /build/dyndns /app/dyndns

# Copy wget and its dependencies for healthcheck
COPY --from=builder /usr/bin/wget /usr/bin/wget
COPY --from=builder /lib/ld-musl-x86_64.so.1 /lib/
COPY --from=builder /lib/libssl.so.3 /lib/
COPY --from=builder /lib/libcrypto.so.3 /lib/
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Use nonroot user
USER nonroot:nonroot

# Expose the application port
EXPOSE 8080

# Add healthcheck
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD [ "/usr/bin/wget", "--quiet", "--spider", "--no-verbose", "http://localhost:8080/status" ]

# Set the entrypoint
ENTRYPOINT ["/app/dyndns"]
