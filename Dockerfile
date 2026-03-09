FROM golang:1.25-alpine AS builder

WORKDIR /build
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o secretscalpel .

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /build/secretscalpel /secretscalpel
COPY --from=builder /build/rules /rules

ENTRYPOINT ["/secretscalpel"]
