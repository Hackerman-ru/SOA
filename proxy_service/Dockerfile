# Используем официальный образ Rust для сборки
FROM rust:1.85 AS builder

# Устанавливаем рабочую директорию
WORKDIR /usr/src/proxy_service

# Копируем зависимости и исходный код
COPY Cargo.toml Cargo.lock ./
COPY src ./src

# Собираем проект
RUN cargo build --release

# Используем минимальный образ для финального контейнера
FROM debian:bookworm-slim

# Устанавливаем рабочую директорию
WORKDIR /app

# Устанавливаем необходимые зависимости
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    libssl3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Копируем собранный бинарник из builder-образа
COPY --from=builder /usr/src/proxy_service/target/release/proxy_service .

# Указываем порт, который будет использовать приложение
EXPOSE 8080

# Команда для запуска приложения
CMD ["./proxy_service"]
