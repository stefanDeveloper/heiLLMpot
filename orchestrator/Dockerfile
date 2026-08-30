# ─── Stage 1: build ──────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake git curl zip unzip ca-certificates pkg-config \
    libssl-dev libpq-dev libmaxminddb-dev \
    && rm -rf /var/lib/apt/lists/*

# Install vcpkg
ENV VCPKG_ROOT=/opt/vcpkg
RUN git clone --depth=1 https://github.com/microsoft/vcpkg.git ${VCPKG_ROOT} \
    && ${VCPKG_ROOT}/bootstrap-vcpkg.sh -disableMetrics

WORKDIR /build
COPY vcpkg.json .
COPY CMakeLists.txt .
COPY src/ src/
COPY sql/ sql/
COPY config/ config/

# Install vcpkg dependencies and build
ARG GITHUB_TOKEN
ENV GITHUB_TOKEN=${GITHUB_TOKEN}
RUN mkdir -p /opt/vcpkg/downloads && \
    curl -sL -H "Authorization: token ${GITHUB_TOKEN}" -o /opt/vcpkg/downloads/Thalhammer-jwt-cpp-v0.7.2.tar.gz https://github.com/Thalhammer/jwt-cpp/archive/v0.7.2.tar.gz && \
    curl -sL -H "Authorization: token ${GITHUB_TOKEN}" -o /opt/vcpkg/downloads/openssl-openssl-openssl-3.6.3.tar.gz https://github.com/openssl/openssl/archive/openssl-3.6.3.tar.gz && \
    cmake -B build \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_TOOLCHAIN_FILE=${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake \
    -DOATPP_SWAGGER_RES_PATH=/app/oatpp-swagger/res \
    && cmake --build build --parallel $(nproc)

RUN swagger_res="$(find /build/build/vcpkg_installed -path '*/bin/oatpp-swagger/res' -type d | head -n 1)" \
    && test -f "${swagger_res}/favicon-16x16.png" \
    && mkdir -p /build/oatpp-swagger \
    && cp -a "${swagger_res}" /build/oatpp-swagger/res

# ─── Stage 2: runtime ────────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 libpq5 libmaxminddb0 ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /build/build/orchestrator /app/orchestrator
COPY --from=builder /build/sql               /app/sql
COPY --from=builder /build/config            /app/config
COPY --from=builder /build/oatpp-swagger/res /app/oatpp-swagger/res

RUN mkdir -p /app/certs /usr/share/GeoIP

ENTRYPOINT ["/app/orchestrator", "/app/config/orchestrator.json"]
