# Dockerfile
FROM debian:bullseye-slim AS runtime

WORKDIR /usr/local/bin

# 런타임 의존성 설치
RUN apt-get update && apt-get install -y \
  libssl-dev \
  ca-certificates \
  && rm -rf /var/lib/apt/lists/*

# 바이너리 복사 (외부 빌드)
COPY ./bolt-sidecar /usr/local/bin/bolt-sidecar

ENTRYPOINT ["/usr/local/bin/bolt-sidecar"]