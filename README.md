# EdutabStore Server

F-Droid repository server for EdutabStore - Educational apps for tablets.

## Quick Start

```bash
# Clone the repository
git clone https://github.com/toekomst-school/EduTabStoreServer.git
cd EduTabStoreServer

# Build and initialize
make setup

# Edit configuration
nano data/config/config.yml

# Add your APKs
cp /path/to/app.apk data/unsigned/

# Update repository index
make update

# Get certificate for client app
make certificate

# Start web server
make nginx
```

Your repository is now available at `http://localhost:8080/repo`

## Commands

| Command | Description |
|---------|-------------|
| `make setup` | First-time setup (build + init) |
| `make update` | Rebuild index after adding APKs |
| `make certificate` | Get certificate for client config |
| `make nginx` | Start web server |
| `make nginx-auto` | Start with auto-updater |
| `make shell` | Debug shell in container |
| `make stop` | Stop all services |
| `make logs` | View nginx logs |
| `make clean` | Remove containers |

## Directory Structure

```
server/
├── Dockerfile              # F-Droid server image
├── docker-compose.yml      # Container orchestration
├── entrypoint.sh           # Container entrypoint
├── nginx.conf              # Web server configuration
├── config.yml.template     # F-Droid config template
├── Makefile                # Convenience commands
└── data/                   # Persistent data (gitignored)
    ├── config/             # config.yml + keystore
    ├── repo/               # Repository index + APKs
    └── unsigned/           # Drop APKs here for import
```

## Adding Apps

1. Copy APK files to `data/unsigned/`
2. Run `make update`
3. Repository index is automatically rebuilt

## Production Deployment

### 1. Secure the keystore password

```bash
cp .env.example .env
nano .env  # Set KEYSTOREPASS to a secure value
```

### 2. Enable HTTPS

1. Obtain SSL certificates (Let's Encrypt recommended)
2. Place certificates in `ssl/` directory
3. Uncomment HTTPS section in `nginx.conf`
4. Update `docker-compose.yml` to mount SSL volume

### 3. Configure DNS

Point `store.edutab.nl` to your server IP.

### 4. Backup

**Critical files to backup:**
- `data/config/keystore.p12` - Repository signing key
- `data/config/config.yml` - Configuration

## Client Configuration

After running `make certificate`, copy the output to your EdutabStore client:

```
client/app/src/edutab/assets/default_repos.json
```

## License

AGPL-3.0 (same as F-Droid)
