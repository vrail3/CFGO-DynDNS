# Build stage
FROM golang:latest AS builder

WORKDIR /build

# Install necessary build tools
RUN apk add --no-cache gcc musl-dev

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary with proper cross-compilation flags
ARG TARGETARCH
ARG TARGETOS
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} CGO_ENABLED=0 go build \
    -ldflags="-w -s" \
    -o dyndns

# Production stage
FROM gcr.io/distroless/static:nonroot

# Copy only the binary from builder
COPY --from=builder /build/dyndns /app/dyndns

# Use nonroot user
USER nonroot:nonroot

# Expose the application port
EXPOSE 8080

# Add healthcheck using native Go binary instead of wget
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/app/dyndns", "-health-check"]

# Set the entrypoint
ENTRYPOINT ["/app/dyndns"]
