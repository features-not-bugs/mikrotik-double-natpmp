# Build stage
FROM golang:1.25-alpine AS builder

WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 go build -a -installsuffix cgo -ldflags '-s -w -extldflags "-static"' -o double-natpmp .

# Final stage - scratch for MikroTik compatibility
FROM scratch

# Copy CA certificates for HTTPS
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the binary from builder
COPY --from=builder /build/double-natpmp /double-natpmp

# Run the binary
ENTRYPOINT ["/double-natpmp"]
