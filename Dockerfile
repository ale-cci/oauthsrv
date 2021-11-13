# create test public key
FROM alpine/openssl as keys
WORKDIR /root
RUN set -ex ; \
    openssl genrsa -des3 -out private.pem 2048 ;\
    openssl rsa -in private.pem -outform PEM -pubout -out public.pem

#
FROM golang:1.16.5-alpine3.14 as base
ARG test_dependencies="gcc musl-dev"
RUN mkdir -p /etc/oauthsrv/.

# development image for fast-reloading and testing
FROM base as testing
RUN adduser -G users -D oauthsrv
COPY --from=keys /root/private.pem /root/public.pem /etc/oauthsrv/

RUN apk add --update ${test_dependencies}


WORKDIR /home/oauthsrv/

USER oauthsrv
COPY ./go.mod ./go.sum ./
RUN go mod download

CMD ["go", "run", "oauthsrv.go"]

