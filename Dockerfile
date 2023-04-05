FROM golang:1.18-alpine as builder

WORKDIR /go/src/app

ADD go.mod /go/src/app
ADD go.sum /go/src/app
RUN go mod download

ADD . /go/src/app
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=${VERSION}" -o /gotlsproxy

FROM scratch

COPY --from=builder /gotlsproxy /gotlsproxy

ARG VERSION=dev
LABEL version="${VERSION}"

ENTRYPOINT [ "/gotlsproxy" ]
CMD [ "-bind", ":8888" ]
