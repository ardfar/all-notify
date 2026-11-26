FROM golang:1.27-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/all-notify-server ./cmd/all-notify-server

FROM alpine:3.21

RUN apk add --no-cache ca-certificates \
    && adduser -D -u 10001 allnotify \
    && mkdir -p /data \
    && chown allnotify:allnotify /data

COPY --from=builder /out/all-notify-server /usr/local/bin/all-notify-server

USER allnotify
WORKDIR /data
VOLUME ["/data"]

ENV ALLNOTIFY_ADDR=:8080 \
    ALLNOTIFY_DATA_DIR=/data

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/all-notify-server"]
CMD ["serve"]
