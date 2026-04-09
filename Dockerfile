# Этап сборки (Builder)
FROM ubuntu:22.04 AS builder
ENV DEBIAN_FRONTEND=noninteractive

# Устанавливаем ограничение на потоки, чтобы сервер не упал от нехватки памяти
ENV VCPKG_MAX_CONCURRENCY=1

# 1. Ставим нужные пакеты (ВНИМАНИЕ: убраны libssl-dev и libpq-dev, чтобы избежать конфликтов с vcpkg)
RUN apt-get update && apt-get install -y build-essential cmake git curl zip unzip tar pkg-config ninja-build bison flex autoconf automake libtool m4 linux-libc-dev python3 python-is-python3

# 2. Скачиваем vcpkg
WORKDIR /build
RUN git clone https://github.com/microsoft/vcpkg.git && ./vcpkg/bootstrap-vcpkg.sh

# 3. МАГИЯ КЭШИРОВАНИЯ: Копируем ТОЛЬКО файл зависимостей
WORKDIR /app
COPY vcpkg.json .

# 4. Запускаем установку тяжелых библиотек.
RUN /build/vcpkg/vcpkg install --triplet x64-linux

# 5. Теперь копируем наш C++ код
COPY . /app

# 6. Быстрая сборка только нашего кода
RUN cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=/build/vcpkg/scripts/buildsystems/vcpkg.cmake -GNinja
RUN cmake --build build --config Release

# ---------------------------------------------------------
# Финальный образ (оставьте без изменений, только проверьте ПРОБЕЛ после CMD)
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y libssl-dev libpq5 && rm -rf /var/lib/apt/lists/*
WORKDIR /app

# Для Auth Server:
COPY --from=builder /app/build/auth-manager-server /app/
CMD ["./auth-manager-server"]
