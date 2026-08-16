# Multi-stage build
FROM golang:1.25-alpine AS builder

# Install dependencies
RUN apk add --no-cache git make

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build API
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o bastion-api ./cmd/bastion-api

# Final stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates git

WORKDIR /root/

# Copy binaries
COPY --from=builder /app/bastion-api .

# Copy configs
COPY --from=builder /app/configs ./configs

EXPOSE 8080

CMD ["./bastion-api"]
