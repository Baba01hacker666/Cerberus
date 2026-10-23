# syntax=docker/dockerfile:1
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/cerberus .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates iptables iproute2 wireguard-tools
COPY --from=build /out/cerberus /usr/local/bin/cerberus
EXPOSE 7443 51820/udp
ENTRYPOINT ["/usr/local/bin/cerberus"]
CMD ["daemon"]
