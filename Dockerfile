# syntax=docker/dockerfile:1

# Build stage: compile a static binary. It runs on the build machine's own
# platform ($BUILDPLATFORM) and cross-compiles for the target, which Go does
# natively, so an arm64 laptop builds the amd64 image without emulation:
#   docker buildx build --platform linux/amd64,linux/arm64 -t redactor .
FROM --platform=$BUILDPLATFORM golang:1.27.2-alpine@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS build
ARG TARGETOS TARGETARCH
WORKDIR /src

# Dependencies first, so this layer stays cached while only code changes.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
# CGO off: a fully static binary that needs no libc in the final image.
# -trimpath and -s -w drop local paths and debug symbols.
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/redactor ./cmd/redactor

# Final stage: distroless "static" has no shell and no package manager,
# only CA certificates, time zone data and a non-root user (65532). Almost
# nothing to attack, and nothing to patch except our own binary.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
COPY --from=build /out/redactor /redactor
# Default rules, so the image also works on its own. In Kubernetes a
# ConfigMap is mounted over /etc/redactor instead.
COPY rules.yaml /etc/redactor/rules.yaml
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/redactor"]
CMD ["--serve", "--addr", ":8080", "--rules", "/etc/redactor/rules.yaml"]
