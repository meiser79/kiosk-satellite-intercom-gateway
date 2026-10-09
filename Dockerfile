# Builds both the standalone container and the Home Assistant add-on.
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/ks-intercom-gateway ./src

FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata
COPY --from=build /out/ks-intercom-gateway /usr/local/bin/ks-intercom-gateway
VOLUME /config
EXPOSE 8099
ENTRYPOINT ["/usr/local/bin/ks-intercom-gateway"]
