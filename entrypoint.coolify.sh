#!/bin/bash
set -e

REPO_DIR="/data/repo"
CONFIG_DIR="/data/config"
UNSIGNED_DIR="/data/unsigned"

# Environment variables with defaults
REPO_NAME="${REPO_NAME:-EdutabStore}"
REPO_DESCRIPTION="${REPO_DESCRIPTION:-Educational apps for tablets}"
REPO_URL="${REPO_URL:-https://store.edutab.nl/repo}"
ARCHIVE_NAME="${ARCHIVE_NAME:-${REPO_NAME} Archive}"
ARCHIVE_DESCRIPTION="${ARCHIVE_DESCRIPTION:-Older versions of ${REPO_NAME} apps}"

echo "=== EdutabStore Server Starting ==="

# Create directories if they don't exist
mkdir -p "$REPO_DIR/repo" "$CONFIG_DIR" "$UNSIGNED_DIR"

# Initialize repository if not done
if [ ! -f "$CONFIG_DIR/config.yml" ]; then
    echo "Initializing F-Droid repository..."
    cd "$REPO_DIR"

    # Initialize fdroid
    fdroid init

    # Move config and keystore to persistent config directory
    mv config.yml "$CONFIG_DIR/" 2>/dev/null || true
    mv keystore.p12 "$CONFIG_DIR/" 2>/dev/null || true

    # Update config with correct paths
    sed -i "s|keystore:.*|keystore: $CONFIG_DIR/keystore.p12|" "$CONFIG_DIR/config.yml"

    echo "Repository initialized!"
    echo ""
    echo "=== IMPORTANT: Save your keystore! ==="
    echo "Backup /data/config/keystore.p12 - this is your signing key!"
    echo ""
fi

# Create symlink to config
ln -sf "$CONFIG_DIR/config.yml" "$REPO_DIR/config.yml"

# Always apply environment config on startup using Python for reliable YAML handling
echo "Applying environment config..."
python3 << PYEOF
import yaml

config_file = "$CONFIG_DIR/config.yml"
with open(config_file, 'r') as f:
    config = yaml.safe_load(f) or {}

# Update from environment variables
config['repo_name'] = "$REPO_NAME"
config['repo_description'] = "$REPO_DESCRIPTION"
config['repo_url'] = "$REPO_URL"
config['archive_name'] = "$ARCHIVE_NAME"
config['archive_description'] = "$ARCHIVE_DESCRIPTION"
config['keystore'] = "$CONFIG_DIR/keystore.p12"

with open(config_file, 'w') as f:
    yaml.dump(config, f, default_flow_style=False, allow_unicode=True)

print(f"Config: repo_name={config['repo_name']}, repo_url={config['repo_url']}")
PYEOF

# Rebuild index with updated config
echo "Rebuilding repository index..."
cd "$REPO_DIR"
fdroid update --create-metadata 2>&1 || echo "Note: fdroid update returned non-zero (may be empty repo)"

# Copy landing page if repo is empty
if [ ! -f "$REPO_DIR/repo/index.html" ] && [ -f "/data/landing.html" ]; then
    cp /data/landing.html "$REPO_DIR/repo/index.html"
fi

# Process any APKs in unsigned folder
if ls "$UNSIGNED_DIR"/*.apk 1>/dev/null 2>&1; then
    echo "Found APKs in unsigned folder, importing..."
    cp "$UNSIGNED_DIR"/*.apk "$REPO_DIR/repo/" 2>/dev/null || true
    cd "$REPO_DIR"
    fdroid update --create-metadata
    echo "Repository updated!"
fi

# Export certificate info
echo ""
echo "=== Repository Certificate ==="
if [ -f "$CONFIG_DIR/keystore.p12" ]; then
    cd "$REPO_DIR"
    # Get fingerprint
    FINGERPRINT=$(keytool -list -keystore "$CONFIG_DIR/keystore.p12" \
        -storepass "${KEYSTOREPASS:-android}" 2>/dev/null | \
        grep -i "SHA256:" | sed 's/.*SHA256: //' | tr -d ':' | tr '[:upper:]' '[:lower:]')
    echo "Fingerprint: $FINGERPRINT"
    echo ""
    echo "For client default_repos.json, run:"
    echo "  docker exec <container> cat /data/config/keystore.p12 | base64"
fi
echo ""

# Configure nginx
rm -f /etc/nginx/sites-enabled/default
ln -sf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default

# Update nginx root
sed -i "s|root /usr/share/nginx/html|root $REPO_DIR|g" /etc/nginx/sites-available/default

echo "Starting nginx..."
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf
