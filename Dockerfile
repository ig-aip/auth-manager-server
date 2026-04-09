# Этап сборки (Builder)
FROM ubuntu:22.04 AS builder
ENV DEBIAN_FRONTEND=noninteractive

# 1. Ставим нужные пакеты. 
# ВАЖНО: Мы добавили сюда libpq-dev и libpqxx-dev
RUN apt-get update && apt-get install -y build-essential cmake git curl zip unzip tar pkg-config ninja-build bison flex autoconf automake libtool m4 linux-libc-dev python3 libpq-dev libpqxx-dev

# 2. Скачиваем vcpkg
WORKDIR /build
RUN git clone https://github.com/microsoft/vcpkg.git && ./vcpkg/bootstrap-vcpkg.sh

# 3. МАГИЯ КЭШИРОВАНИЯ: Копируем ТОЛЬКО файл зависимостей
WORKDIR /app
COPY vcpkg.json .

# 4. Запускаем установку зависимостей через vcpkg (теперь он пропустит libpqxx и соберет всё остальное)
RUN /build/vcpkg/vcpkg install --triplet x64-linux

# 5. Теперь копируем наш C++ код
COPY . /app

# 6. Сборка кода. CMake автоматически найдет системные libpqxx и libpq
RUN cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=/build/vcpkg/scripts/buildsystems/vcpkg.cmake -GNinja
RUN cmake --build build --config Release

# ---------------------------------------------------------
# Финальный образ
FROM ubuntu:22.04
# ВАЖНО: Добавляем libpq5 и libpqxx-dev в финальный образ, чтобы программа могла запуститься
RUN apt-get update && apt-get install -y libssl-dev libpq5 libpqxx-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /app

# Для Auth Server (или Music Server, раскомментируйте нужный):
COPY --from=builder /app/build/auth-manager-server /app/
CMD ["./auth-manager-server"]
