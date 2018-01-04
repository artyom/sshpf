# -- Go Builder Image --
FROM golang:1.8-alpine AS builder

RUN apk add --no-cache git
COPY . /go/src/sshpf
WORKDIR /go/src/sshpf

RUN set -ex \
    && go get -v \
    && go build -v -o "/sshpf"

# -- dex-app Image --
FROM alpine:3.6
RUN set -ex \
    && apk add --no-cache bash ca-certificates

COPY --from=builder /sshpf /bin/sshpf
ENTRYPOINT [ "/bin/sshpf" ]
