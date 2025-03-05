# Используем официальный образ Rust для сборки
FROM rust:1.85 AS builder

# Устанавливаем рабочую директорию
WORKDIR /usr/src/user_service

# Копируем зависимости и исходный код
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY migrations ./migrations
COPY .sqlx ./.sqlx

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
COPY --from=builder /usr/src/user_service/target/release/user_service .

# Копируем папку с миграциями
COPY --from=builder /usr/src/user_service/migrations ./migrations

# Копируем .env файл (если нужно)
COPY .env .

# Указываем порт, который будет использовать приложение
EXPOSE 8081

# Команда для запуска приложения
ENTRYPOINT ["./user_service"]
