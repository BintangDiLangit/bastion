FROM golang:1.21-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o /bin/scanner-cli ./cmd/cli

FROM alpine:latest

RUN apk --no-cache add git ca-certificates

WORKDIR /app

COPY --from=builder /bin/scanner-cli /bin/scanner-cli
COPY --from=builder /app/configs ./configs

ENTRYPOINT ["/bin/scanner-cli"]
