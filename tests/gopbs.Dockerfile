# Build context is the repository root (see compose.yml).
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /gopbs-pxar ./cmd/gopbs-pxar

FROM alpine:3.20

RUN addgroup -g 1000 gopbs && adduser -S -u 1000 -G gopbs gopbs
USER gopbs

COPY --from=build /gopbs-pxar /usr/local/bin/gopbs-pxar
ENTRYPOINT ["gopbs-pxar"]
