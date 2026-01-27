#!/bin/bash
set -e

REPO_DIR="/data/repo"
CONFIG_DIR="/data/config"
UNSIGNED_DIR="/data/unsigned"

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

    # Set repo URL from environment or default
    REPO_URL="${REPO_URL:-https://store.edutab.nl/repo}"
    sed -i "s|repo_url:.*|repo_url: $REPO_URL|" "$CONFIG_DIR/config.yml"

    echo "Repository initialized!"
    echo ""
    echo "=== IMPORTANT: Save your keystore! ==="
    echo "Backup /data/config/keystore.p12 - this is your signing key!"
    echo ""
fi

# Create symlink to config
ln -sf "$CONFIG_DIR/config.yml" "$REPO_DIR/config.yml"

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
