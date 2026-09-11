# syntax=docker/dockerfile:1

# Build stage — cross-compile the C2 server for linux/amd64.
FROM golang:1.24-alpine AS build
WORKDIR /src

COPY go.mod ./
COPY cmd/ cmd/
COPY server/ server/
COPY channels/ channels/
COPY crypto/ crypto/
COPY patches/ patches/

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -trimpath -ldflags "-s -w" \
    -o /out/voidsyscall-server ./cmd/server

# Runtime stage — alpine keeps the CA bundle so the DoH and HTTPS
# outbound paths can validate TLS from inside the container.
FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata
COPY --from=build /out/voidsyscall-server /usr/bin/voidsyscall-server

# HTTPS beacon endpoint. DNS (53/tcp+udp) is exposed for the DNS channel.
EXPOSE 443/tcp 53/tcp 53/udp

ENTRYPOINT ["/usr/bin/voidsyscall-server"]
CMD ["-http-addr", "0.0.0.0", "-https-port", "443", "-dns-addr", "0.0.0.0", "-dns-port", "53", "-icmp-addr", "0.0.0.0", "-cert", "/certs/server.crt", "-key", "/certs/server.key"]