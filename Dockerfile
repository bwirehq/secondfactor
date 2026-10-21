FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/secondfactor ./cmd/secondfactor
RUN go work init . ./examples/go-http && CGO_ENABLED=0 go build -trimpath -o /out/demo ./examples/go-http
FROM alpine:3.23
RUN apk add --no-cache ca-certificates && addgroup -g 10001 sf && adduser -D -u 10001 -G sf sf
COPY --from=build /out/secondfactor /usr/local/bin/secondfactor
COPY --from=build /out/demo /usr/local/bin/secondfactor-demo
USER 10001:10001
WORKDIR /app
ENTRYPOINT ["secondfactor"]
CMD ["serve","--config","/app/config.json"]
