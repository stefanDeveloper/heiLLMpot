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
COPY third_party/ third_party/

ARG GITHUB_TOKEN
ENV GITHUB_TOKEN=${GITHUB_TOKEN}
RUN mkdir -p /opt/vcpkg/downloads && \
    curl -sL -H "Authorization: token ${GITHUB_TOKEN}" -o /opt/vcpkg/downloads/Thalhammer-jwt-cpp-v0.7.2.tar.gz https://github.com/Thalhammer/jwt-cpp/archive/v0.7.2.tar.gz && \
    curl -sL -H "Authorization: token ${GITHUB_TOKEN}" -o /opt/vcpkg/downloads/openssl-openssl-openssl-3.6.3.tar.gz https://github.com/openssl/openssl/archive/openssl-3.6.3.tar.gz && \
    cmake -B build \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_TOOLCHAIN_FILE=${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake \
    && cmake --build build --parallel $(nproc)

RUN mkdir -p /build/out_libs && cp -a /build/build/vcpkg_installed/*/lib/* /usr/local/lib/ || true

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
RUN cp /build/build/honeypot /app/honeypot && cp -r /build/config /app/config

RUN ldconfig && mkdir -p /app/generated_sites /app/certs /app/logs

EXPOSE 8081 8443 2222

ENTRYPOINT ["/app/honeypot", "/app/config/honeypot.json"]
