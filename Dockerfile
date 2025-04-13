FROM golang:1.24-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go install github.com/pressly/goose/v3/cmd/goose@latest
RUN CGO_ENABLED=0 GOOS=linux go build -o myapp ./cmd/service

FROM alpine:latest

WORKDIR /app

COPY --from=builder /app/myapp .
COPY --from=builder /go/bin/goose /usr/local/bin/goose

COPY internal/migrations /app/migrations
COPY config.dev.yaml /app/config.dev.yaml

EXPOSE 8080

CMD ["./myapp"]