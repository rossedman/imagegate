# Built by GoReleaser (dockers_v2): the build context holds one binary per
# platform under $TARGETPLATFORM/. distroless/static has CA certificates and
# no shell. It runs as root: imagegate needs the dockerd socket and creates
# the plugin socket.
FROM gcr.io/distroless/static-debian12:latest
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/imagegate /usr/bin/imagegate
ENTRYPOINT ["/usr/bin/imagegate"]
CMD ["serve"]
