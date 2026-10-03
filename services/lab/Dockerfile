# Single image carrying every Go service in the lab. One build, five binaries,
# no module downloads: the project has no third-party dependencies on purpose
# so it builds on a machine that has never seen it before.
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY internal ./internal
COPY cmd ./cmd
RUN go vet ./... && \
    go test ./... && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /bin/firewall ./cmd/firewall && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /bin/dnsguard ./cmd/dnsguard && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /bin/attacker ./cmd/attacker && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /bin/site     ./cmd/site && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /bin/labca    ./cmd/labca && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /bin/ctl      ./cmd/ctl

FROM alpine:3.20
RUN adduser -D -u 10001 lab
COPY --from=build /bin/firewall /bin/dnsguard /bin/attacker /bin/site /bin/labca /bin/ctl /usr/local/bin/
ENV PATH=/usr/local/bin:$PATH
WORKDIR /
CMD ["firewall"]
