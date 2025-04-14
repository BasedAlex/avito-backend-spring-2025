.PHONY: build up run down integration test cover check restart

# Сборка Docker-контейнеров
build:
	docker compose build

# Запуск контейнеров
up:
	docker compose up -d

# Сборка и запуск контейнеров
run: build up

# Остановка контейнеров
down:
	docker compose down

# Запуск интеграционных тестов
integration:
	go test -v ./internal/tests

# Запуск юнит тестов
test:
	go test -v ./internal/service
	go test -v ./internal/auth

# Покрытие тестов с выводом в HTML
cover:
	go test ./... -coverprofile=c.out
	go tool cover -html=c.out

# Запуск всех тестов
check: test integration

# Сгенерировать DTO из swagger.yaml
generate:
	oapi-codegen -generate types,chi-server,spec -package=dto swagger.yaml > internal/generated/dto.gen.go

# Перезапустить контейнеры
restart: down up