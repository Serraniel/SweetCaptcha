# syntax=docker/dockerfile:1
# Base images are pinned by digest. Dependabot opens a PR when a digest changes.

FROM node:24-alpine@sha256:a34ab6d7f6f4813f4d0c5469d74685604b962fbdbf5793a7bc7b4998ecb867c8 AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
COPY internal/assets/dist/core/.gitkeep /src/internal/assets/dist/core/.gitkeep
RUN node build.mjs && npm test

FROM golang:1.27-alpine@sha256:fa3d596898d9f126af7c01d14ee7597bab3f39cccf392ef36b69fe77cd681f18 AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ cmd/
COPY internal/ internal/
COPY --from=web /src/internal/assets/dist/ internal/assets/dist/
ENV CGO_ENABLED=0
RUN mkdir -p /out/data/ipdata \
 && go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/sweetcaptcha ./cmd/sweetcaptcha \
 && go build -trimpath -ldflags "-s -w -X main.version=${VERSION}-strict" -tags strictonly -o /out/sweetcaptcha-strict ./cmd/sweetcaptcha

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
