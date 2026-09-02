FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/hub ./cmd/hub && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/agent ./cmd/agent && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/gateway ./cmd/gateway && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/migrate ./cmd/migrate
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/hub /hub
COPY --from=build /out/agent /agent
COPY --from=build /out/gateway /gateway
COPY --from=build /out/migrate /migrate
USER 65532:65532
ENTRYPOINT ["/hub"]
