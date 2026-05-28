FROM debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake git curl zip unzip ca-certificates pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

ENV VCPKG_ROOT=/opt/vcpkg
RUN git clone --depth=1 https://github.com/microsoft/vcpkg.git ${VCPKG_ROOT} \
    && ${VCPKG_ROOT}/bootstrap-vcpkg.sh -disableMetrics

WORKDIR /build
COPY vcpkg.json .
COPY CMakeLists.txt .
COPY include/ include/
COPY src/ src/
COPY config/ config/

RUN cmake -B build \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_TOOLCHAIN_FILE=${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake \
    && cmake --build build --parallel $(nproc)

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /build/build/honeypot /app/honeypot
COPY --from=builder /build/build/vcpkg_installed/x64-linux/lib/ /usr/local/lib/
COPY --from=builder /build/config /app/config

RUN ldconfig && mkdir -p /app/generated_sites /app/certs /app/logs

EXPOSE 8081 8443 2222

ENTRYPOINT ["/app/honeypot", "/app/config/honeypot.json"]
