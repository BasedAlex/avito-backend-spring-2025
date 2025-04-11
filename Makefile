# Makefile

.PHONY: build up down lint integration test fmt check restart

# Собрать Docker-контейнеры
build:
	@docker compose build

# Запустить контейнеры
up:
	@docker compose up -d

# Собрать Docker и запустить контейнеры
run: build up

# Остановить контейнеры
down:
	@docker compose down

# Запустить линтер
lint:
	@golangci-lint run ./...

# Запустить интеграционные тесты
integration:
	@go test -v ./internal/tests

# Запустить юнит тесты
test:
	@go test -v ./internal/service

# Форматировать код
fmt:
	@go fmt ./...

# Запустить линтер и тесты
check: lint test integration

# Перезапустить контейнеры
restart: down up