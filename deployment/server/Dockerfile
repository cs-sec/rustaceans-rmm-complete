# Multi-stage build for Rustaceans RMM Server
FROM rust:1.75-slim as builder

# Install system dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy Cargo files
COPY Cargo.toml Cargo.lock ./

# Copy source code
COPY src ./src
COPY static ./static

# Build the application
RUN cargo build --release --bin simple-rmm-server

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r rmm && useradd -r -g rmm rmm

# Set working directory
WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /app/target/release/simple-rmm-server /app/
COPY --from=builder /app/static ./static

# Create directories
RUN mkdir -p /app/logs /app/certs && \
    chown -R rmm:rmm /app

# Switch to non-root user
USER rmm

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

# Start the server
CMD ["./simple-rmm-server"]