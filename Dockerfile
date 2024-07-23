##
## Build did driver
##
FROM golang:1.18-alpine AS base

WORKDIR /build

RUN apk add --no-cache --update git

COPY ./cmd ./cmd
COPY ./pkg ./pkg
COPY go.mod ./
COPY go.sum ./
RUN go mod download

RUN CGO_ENABLED=0 go build -o ./driver ./cmd/driver/main.go

# Build an driver image
FROM scratch

COPY ./resolvers.settings.yaml /app/resolvers.settings.yaml
COPY --from=base /build/driver /app/driver
COPY --from=base /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

WORKDIR /app

ENV HOST=0.0.0.0
ENV PORT=8080

# Command to run
ENTRYPOINT ["/app/driver", "/app/resolvers.settings.yaml"]
