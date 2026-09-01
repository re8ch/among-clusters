FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/hub ./cmd/hub && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/agent ./cmd/agent
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/hub /hub
COPY --from=build /out/agent /agent
USER 65532:65532
ENTRYPOINT ["/hub"]
