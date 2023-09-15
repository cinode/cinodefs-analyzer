# syntax=docker/dockerfile:1
ARG GO_VERSION=1.21

# Base image with go compiler and tested source code
FROM --platform=$BUILDPLATFORM docker.io/library/golang:${GO_VERSION} as build

# Compile and test with non-root user
RUN useradd -ms /bin/bash go
USER go
RUN git config --global --add safe.directory /home/go/app

# Fetch and verify dependencies
WORKDIR /home/go/app
COPY go.mod go.sum ./
RUN go mod download
RUN go mod verify

# Bring in and test the source code
COPY . .
# RUN go vet -v ./...
# RUN go test -v ./...

# Build binary
ENV CGO_ENABLED=0
ARG TARGETOS TARGETARCH
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} GOARM=${TARGETVARIANT#v} \
    go build \
        -v \
        -ldflags="-w -s" \
        -o "/home/go/cinodefs_analyzer" \
        "./cmd/cinodefs_analyzer"

# Force distroless base to use current platform (most likely linux/amd64)
# which is needed since distroless/static is not available for linux/arm/v6
FROM --platform=$BUILDPLATFORM gcr.io/distroless/static as distroless

FROM scratch
COPY --from=distroless / /
COPY --from=build "/home/go/cinodefs_analyzer" "/usr/sbin/cinodefs_analyzer"
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT [ "/usr/sbin/cinodefs_analyzer" ]
