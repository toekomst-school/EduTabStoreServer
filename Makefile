.PHONY: build init update shell nginx stop clean certificate help

# Default target
help:
	@echo "EdutabStore Server Commands"
	@echo "==========================="
	@echo ""
	@echo "Setup:"
	@echo "  make build       - Build the Docker image"
	@echo "  make init        - Initialize the repository (first time only)"
	@echo "  make setup       - Full setup (build + init + configure)"
	@echo ""
	@echo "Operations:"
	@echo "  make update      - Update repository index after adding APKs"
	@echo "  make certificate - Get certificate for client app"
	@echo "  make shell       - Open shell in fdroid container"
	@echo ""
	@echo "Server:"
	@echo "  make nginx       - Start nginx web server"
	@echo "  make stop        - Stop all containers"
	@echo "  make logs        - View nginx logs"
	@echo ""
	@echo "Maintenance:"
	@echo "  make clean       - Remove containers (keeps data)"
	@echo "  make clean-all   - Remove everything including data"
	@echo ""
	@echo "Workflow:"
	@echo "  1. make setup"
	@echo "  2. Edit data/config/config.yml"
	@echo "  3. Copy APKs to data/unsigned/"
	@echo "  4. make update"
	@echo "  5. make certificate (copy to client)"
	@echo "  6. make nginx"

# Build the fdroid Docker image
build:
	docker compose build fdroid

# Initialize repository
init: build
	@mkdir -p data/repo data/config data/unsigned
	docker compose run --rm fdroid init

# Full setup
setup: build
	@mkdir -p data/repo data/config data/unsigned
	@cp -n .env.example .env 2>/dev/null || true
	docker compose run --rm fdroid init
	@if [ ! -f data/config/config.yml ]; then \
		cp config.yml.template data/config/config.yml; \
		echo "Created data/config/config.yml - please edit it!"; \
	fi
	@echo ""
	@echo "Setup complete! Next steps:"
	@echo "1. Edit data/config/config.yml with your settings"
	@echo "2. Copy APKs to data/unsigned/"
	@echo "3. Run: make update"

# Update repository
update:
	docker compose run --rm fdroid update

# Get certificate for client
certificate:
	@echo ""
	@echo "Copy this certificate string to your client's default_repos.json:"
	@echo ""
	@docker compose run --rm fdroid certificate

# Open shell
shell:
	docker compose run --rm fdroid shell

# Start nginx
nginx:
	docker compose up -d nginx

# Start with auto-updater
nginx-auto:
	docker compose --profile auto-update up -d nginx updater

# Stop containers
stop:
	docker compose down

# View logs
logs:
	docker compose logs -f nginx

# Clean containers
clean:
	docker compose down --rmi local

# Clean everything
clean-all:
	docker compose down --rmi local -v
	rm -rf data/
