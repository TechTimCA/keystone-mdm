FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /keystone ./cmd/keystone

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /keystone /keystone
ENV KEYSTONE_DATA_DIR=/data KEYSTONE_LISTEN=:8080
VOLUME /data
EXPOSE 8080
USER nonroot
ENTRYPOINT ["/keystone"]
