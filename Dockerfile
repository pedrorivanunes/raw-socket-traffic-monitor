# Two images from one file.
#
#   --target tests  builds everything and runs the suite, including under the
#                   sanitizers. This is how the project is built and tested on
#                   a machine that is not Linux: AF_PACKET, /dev/net/tun and
#                   netpacket/packet.h do not exist anywhere else, so without a
#                   container there is nothing to compile against.
#
#   --target lab    the runtime image used by docker-compose.yml, which stands
#                   in for the three virtual machines the project was written
#                   on. It carries the two binaries plus the network tools the
#                   tunnel scripts call.
#
#   docker build --target tests -t monitor-tests .
#   docker run --rm monitor-tests

# ---------------------------------------------------------------- build stage

FROM debian:bookworm-slim AS build

# clang is here so the build can be checked against a second compiler; the two
# disagree about enough warnings to make it worth the download.
#
# libclang-rt-14-dev is the part that is easy to miss. Debian splits clang's
# sanitizer runtime into its own package, so without it `make CC=clang sanitize`
# compiles and then fails at the link step looking for libclang_rt.asan. gcc
# carries its runtime in libc6-dev and needs nothing extra.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        clang \
        cppcheck \
        gcc \
        libc6-dev \
        libclang-rt-14-dev \
        make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY Makefile ./
COPY src ./src
COPY tests ./tests
COPY tunnel ./tunnel

RUN make all

# ---------------------------------------------------------------- test image

FROM build AS tests

# Unbuffered output: CI pipes this, and a piped stdout makes the C runtime
# switch to block buffering, so a killed run would show nothing at all.
ENV LSAN_OPTIONS=verbosity=0

# `check` is `test` plus `sanitize`, so a green run here means the suite passed
# both as a normal build and under AddressSanitizer and UBSan.
CMD ["make", "check"]

# ----------------------------------------------------------------- lab image

FROM debian:bookworm-slim AS lab

# iproute2  -> `ip`, which the tunnel scripts use to configure tun0
# iptables  -> the MASQUERADE rule that gives the clients a way out
# curl      -> what the clients use to generate traffic
# procps    -> pgrep, for the entrypoint's health checks
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        iproute2 \
        iptables \
        procps \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /app/build/monitor /usr/local/bin/monitor
COPY --from=build /app/build/traffic_tunnel /usr/local/bin/traffic_tunnel

# The tunnel runs its setup script with execv() and a bare filename, which
# resolves against the working directory -- so the scripts have to be here.
WORKDIR /opt/lab
COPY tunnel/server.sh tunnel/client1.sh tunnel/client2.sh ./
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x ./*.sh /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
