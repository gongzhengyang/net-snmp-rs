# syntax=docker/dockerfile:1
#
# net-snmp-rs container image (static musl binaries).
#
# This image performs NO compilation. The binaries are built locally on the
# host with a release musl build and then copied into a minimal alpine image:
#
#     just build-musl        # cargo build --release --target x86_64-unknown-linux-musl
#     just docker-build      # build-musl (above) + docker compose build
#
# The musl target produces fully static executables (the C runtime is linked
# statically), so they run on the bare alpine base with no glibc/runtime
# dependency. `.dockerignore` excludes target/ except for exactly these
# binaries, keeping the build context tiny.

FROM alpine:3.20 AS deploy
LABEL org.opencontainers.image.title="net-snmp-rs" \
      org.opencontainers.image.description="Rust SNMP agent + command-line tools (static musl build)" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"

# Optional Alpine package mirror *host* (empty = upstream), e.g.
#   docker build --build-arg APK_MIRROR=mirrors.ustc.edu.cn .
ARG APK_MIRROR=""

# Static musl binaries need no runtime libs; ca-certificates is kept for TLS.
RUN if [ -n "$APK_MIRROR" ]; then \
        sed -i "s|dl-cdn.alpinelinux.org|${APK_MIRROR}|g" /etc/apk/repositories; \
    fi \
    && apk add --no-cache ca-certificates

# Copy the locally-built static release binaries. `.dockerignore` re-includes
# only the binaries under this directory, so this brings in just the 20 tools
# (snmpd, the snmp* CLIs, and snmp-itest) and nothing else from target/.
COPY target/x86_64-unknown-linux-musl/release/ /usr/local/bin/

# Configuration files, read via SNMPCONFPATH.
COPY docker/etc-snmp/ /etc/snmp/

ENV SNMPCONFPATH=/etc/snmp \
    MIBDIRS=/usr/share/snmp/mibs \
    RUST_LOG=info

EXPOSE 161/udp

# Default container role: run the SNMP agent in the foreground.
CMD ["snmpd", "0.0.0.0:161"]
