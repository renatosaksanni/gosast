# Dockerfile

FROM golang:1.20-alpine

# Install git (required for fetching dependencies)
RUN apk add --no-cache git

# Set environment variables
ENV GO111MODULE=on

# Set working directory
WORKDIR /app

# Copy go.mod and go.sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod tidy

# Copy the source code
COPY . .

# Build the binary
RUN go build -o gosast ./cmd/gosast

# Set entrypoint
ENTRYPOINT ["./gosast"]
