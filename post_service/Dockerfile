# Используем официальный образ Rust для сборки
FROM rust:1.87 AS builder

# Устанавливаем рабочую директорию
WORKDIR /usr/src/post_service

# Копируем зависимости и исходный код
COPY Cargo.toml Cargo.lock build.rs ./
COPY src ./src
COPY proto ./proto

# Устанавливаем Protoc
RUN apt update && apt install --no-install-recommends --assume-yes \
    protobuf-compiler

# Собираем проект
RUN cargo build --release

# Используем минимальный образ для финального контейнера
FROM debian:bookworm-slim

# Устанавливаем рабочую директорию
WORKDIR /app

# Копируем собранный бинарник из builder-образа
COPY --from=builder /usr/src/post_service/target/release/post_service .

# Указываем порт, который будет использовать приложение
EXPOSE 8082

# Команда для запуска приложения
ENTRYPOINT ["./post_service"]
