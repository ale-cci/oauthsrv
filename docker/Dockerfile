FROM golang:1.16.5-alpine3.14 as base
ARG test_dependencies="gcc musl-dev"

FROM base as testing
RUN adduser -G users -D oauthsrv
RUN apk add --update ${test_dependencies}

WORKDIR /home/oauthsrv/
USER oauthsrv
COPY ./go.mod ./go.sum ./
RUN go mod download

CMD ["go", "run", "oauthsrv.go"]
