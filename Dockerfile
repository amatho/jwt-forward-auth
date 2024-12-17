FROM golang:1.23

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY *.go ./

RUN CGO_ENABLED=0 GOOS=linux go build -o /jwt-forward-auth

EXPOSE 8080

CMD ["/jwt-forward-auth"]
