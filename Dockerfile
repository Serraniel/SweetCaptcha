# syntax=docker/dockerfile:1
# Base images are pinned by digest. Dependabot opens a PR when a digest changes.

FROM node:24-alpine@sha256:116b800c3754b440ee0aa3ed2f20f5bf3d99a554bfd9adeea09ea8017f6e85f5 AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
COPY internal/assets/dist/core/.gitkeep /src/internal/assets/dist/core/.gitkeep
RUN node build.mjs && npm test

FROM golang:1.27-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ cmd/
COPY internal/ internal/
COPY --from=web /src/internal/assets/dist/ internal/assets/dist/
ENV CGO_ENABLED=0
RUN mkdir -p /out/data/ipdata \
 && go build -trimpath -ldflags "-s -w -X github.com/Serraniel/SweetCaptcha/internal/edition.Version=${VERSION}" -o /out/sweetcaptcha ./cmd/sweetcaptcha \
 && go build -trimpath -ldflags "-s -w -X github.com/Serraniel/SweetCaptcha/internal/edition.Version=${VERSION}-strict" -tags strictonly -o /out/sweetcaptcha-strict ./cmd/sweetcaptcha

# Strict-only image: proof of work only. The collectors and the risk engine are not
# compiled in or embedded, so no configuration can turn them on.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab AS strict
COPY --from=build /out/sweetcaptcha-strict /sweetcaptcha
EXPOSE 8080
ENTRYPOINT ["/sweetcaptcha"]

# Default image: standard and strict modes, selected per site. Keep this stage last,
# so a plain `docker build` produces it.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab AS standard
COPY --from=build /out/sweetcaptcha /sweetcaptcha
COPY --from=build --chown=65532:65532 /out/data /data
EXPOSE 8080
ENTRYPOINT ["/sweetcaptcha"]
