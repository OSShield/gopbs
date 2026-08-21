FROM debian:latest

WORKDIR /app

COPY ./tizbac /app

RUN apt-get update && apt-get install -y ca-certificates && update-ca-certificates && apt-get -y install golang && go build -o directorybackup main.go

FROM debian:latest

RUN groupadd --gid 1000 gopbs && useradd --system --uid 1000 --gid 1000 gopbs

USER gopbs

COPY --from=0 /app/directorybackup /usr/local/bin

ENTRYPOINT ["directorybackup"]