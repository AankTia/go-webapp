.PHONY: build run test migrate-up migrate-down docker-build docker-run

build:
	go build -o bin/webapp ./cmd/web

run: build
	./bin/webapp

test:
	go test -v ./...

migrate-up:
	goose -dir migrations sqlite3 webapp.db up 
	
migrate-down:
	goose -dir migrations sqlite3 webapp.db down

docker-build:
	docker-compose build

docker-run:
	docker-compose up -d