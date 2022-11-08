# syntax=docker.io/docker/dockerfile:1
FROM golang:1.19-alpine AS builder

COPY . /app
RUN --mount=type=cache,target=/root/.cache/go-build \
    cd /app && go build -o sdp .

FROM alpine:3.14

COPY --from=builder /app/sdp /usr/local/bin/sdp

RUN addgroup -S sdp && adduser -S -G sdp sdp
USER sdp

ENTRYPOINT ["/usr/local/bin/sdp"]
VOLUME /data

CMD []