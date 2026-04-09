# Этап сборки (Builder)
FROM ubuntu:22.04 AS builder
ENV DEBIAN_FRONTEND=noninteractive

# 1. Ставим все-все нужные пакеты (включая python3)
RUN apt-get update && apt-get install -y build-essential cmake git curl zip unzip tar pkg-config ninja-build libssl-dev libpq-dev bison flex autoconf automake libtool m4 linux-libc-dev python3

# 2. Скачиваем vcpkg
WORKDIR /build
RUN git clone https://github.com/microsoft/vcpkg.git && ./vcpkg/bootstrap-vcpkg.sh

# 3. МАГИЯ КЭШИРОВАНИЯ: Копируем ТОЛЬКО файл зависимостей
WORKDIR /app
COPY vcpkg.json .

# 4. Запускаем установку тяжелых библиотек. Если vcpkg.json не менялся — Docker возьмет это из кэша мгновенно!
RUN /build/vcpkg/vcpkg install --triplet x64-linux

# 5. Теперь копируем наш C++ код
COPY . /app

# 6. Быстрая сборка только нашего кода
RUN cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=/build/vcpkg/scripts/buildsystems/vcpkg.cmake -GNinja
RUN cmake --build build --config Release

# Финальный образ
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y libssl-dev libpq5 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
# Для Music Server напишите streaming-audio-server
COPY --from=builder /app/build/auth-manager-server /app/
CMD ["./auth-manager-server"]