# Builds cmd/conformance-issuer for the docker-compose setup in this
# directory. Build context is the repo root (../.. from here) —
# mirrors conformance/verifier/Dockerfile and
# conformance/wallet-vp/Dockerfile exactly.
FROM golang:1.26@sha256:d7722066f0b60ceccb6c0643cbed1f5f9e15506ac237146c95333504d7805d89 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -o /out/conformance-issuer ./cmd/conformance-issuer

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/conformance-issuer /conformance-issuer
ENTRYPOINT ["/conformance-issuer"]
