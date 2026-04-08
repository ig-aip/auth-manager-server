# Этап сборки (Builder)
FROM ubuntu:22.04 AS builder
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y build-essential cmake git curl zip unzip tar pkg-config ninja-build libssl-dev libpq-dev

WORKDIR /build
RUN git clone https://github.com/microsoft/vcpkg.git && ./vcpkg/bootstrap-vcpkg.sh
COPY . /app
WORKDIR /app
# Сборка проекта
RUN cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=/build/vcpkg/scripts/buildsystems/vcpkg.cmake -GNinja
RUN cmake --build build --config Release

# Финальный образ (легкий)
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y libssl-dev libpq5 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
# Копируем бинарник из builder
COPY --from=builder /app/build/auth-manager-server /app/
# (Для Auth Server вместо file-manager-server напишите auth-manager-server)
CMD ["./auth-manager-server"]