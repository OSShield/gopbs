FROM golang:1

WORKDIR /app

ADD . .

RUN go build -o gopbs .

FROM debian:latest

USER 1000:1000

COPY --from=0 /app/gopbs /usr/local/bin/gopbs

ENTRYPOINT ["gopbs"]