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
RUN cmake -B build \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_TOOLCHAIN_FILE=${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake \
    -DOATPP_SWAGGER_RES_PATH=/build/build/vcpkg_installed/x64-linux/share/oatpp-swagger/res \
    && cmake --build build --parallel $(nproc)

# ─── Stage 2: runtime ────────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 libpq5 libmaxminddb0 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /build/build/orchestrator /app/orchestrator
COPY --from=builder /build/sql               /app/sql
COPY --from=builder /build/config            /app/config

RUN mkdir -p /app/certs /usr/share/GeoIP

ENTRYPOINT ["/app/orchestrator", "/app/config/orchestrator.json"]
