#!/bin/bash
set -e

CONFIG_FILE="/config/config.yml"
REPO_DIR="/repo"

# Initialize repo if not already done
init_repo() {
    if [ ! -f "$REPO_DIR/config.yml" ] && [ ! -L "$REPO_DIR/config.yml" ]; then
        echo "Initializing F-Droid repository..."
        cd "$REPO_DIR"
        fdroid init

        # Link config from /config volume if exists
        if [ -f "$CONFIG_FILE" ]; then
            rm -f "$REPO_DIR/config.yml"
            ln -s "$CONFIG_FILE" "$REPO_DIR/config.yml"
            echo "Linked config from /config/config.yml"
        else
            # Move generated config to /config volume
            mv "$REPO_DIR/config.yml" "$CONFIG_FILE"
            ln -s "$CONFIG_FILE" "$REPO_DIR/config.yml"
            echo "Config moved to /config/config.yml"

            # Set proper defaults for EdutabStore
            sed -i 's/repo_name: .*/repo_name: EdutabStore/' "$CONFIG_FILE"
            sed -i 's/repo_description: .*/repo_description: Educational apps for tablets/' "$CONFIG_FILE"
            sed -i 's/archive_name: .*/archive_name: EdutabStore Archive/' "$CONFIG_FILE"
            sed -i 's/archive_description: .*/archive_description: Older versions of EdutabStore apps/' "$CONFIG_FILE"
            echo "Set EdutabStore defaults in config"
        fi

        # Move keystore to config volume if generated
        if [ -f "$REPO_DIR/keystore.p12" ]; then
            mv "$REPO_DIR/keystore.p12" "/config/keystore.p12"
            echo "Keystore moved to /config/keystore.p12"
        fi

        echo "Repository initialized!"
    else
        echo "Repository already initialized."
        # Ensure symlink exists
        if [ -f "$CONFIG_FILE" ] && [ ! -L "$REPO_DIR/config.yml" ]; then
            rm -f "$REPO_DIR/config.yml"
            ln -s "$CONFIG_FILE" "$REPO_DIR/config.yml"
        fi
    fi
}

# Update repository index
update_repo() {
    echo "Updating repository index..."
    cd "$REPO_DIR"

    # Copy any new APKs from unsigned folder
    if [ -d "/unsigned" ] && [ "$(ls -A /unsigned/*.apk 2>/dev/null)" ]; then
        echo "Found APKs in /unsigned, copying to repo..."
        cp /unsigned/*.apk "$REPO_DIR/repo/" 2>/dev/null || true
    fi

    fdroid update --create-metadata --verbose
    echo "Repository updated!"
}

# Sign unsigned APKs
sign_apks() {
    echo "Signing APKs..."
    cd "$REPO_DIR"
    fdroid publish --verbose
    echo "APKs signed!"
}

# Show repository fingerprint
show_fingerprint() {
    cd "$REPO_DIR"
    if [ -f "repo/index-v2.json" ] || [ -f "repo/index-v1.jar" ]; then
        echo ""
        echo "=== Repository Information ==="
        fdroid repomaker --show-config 2>/dev/null || true
        echo ""
        echo "=== Certificate Fingerprint ==="
        # Extract fingerprint from the keystore
        if [ -f "/config/keystore.p12" ]; then
            keytool -list -keystore /config/keystore.p12 -storepass:env KEYSTOREPASS 2>/dev/null | grep -i "fingerprint" || \
            echo "Set KEYSTOREPASS environment variable to view fingerprint"
        fi
    else
        echo "Repository not yet built. Run 'update' first."
    fi
}

# Export certificate for client configuration
export_certificate() {
    cd "$REPO_DIR"
    if [ -f "/config/keystore.p12" ]; then
        echo ""
        echo "=== Certificate for default_repos.json ==="
        echo ""
        # Export the certificate in hex format
        keytool -exportcert -keystore /config/keystore.p12 \
            -alias repokey \
            -storepass:env KEYSTOREPASS 2>/dev/null | xxd -p | tr -d '\n'
        echo ""
        echo ""
    else
        echo "Keystore not found. Initialize the repository first."
    fi
}

print_help() {
    echo ""
    echo "EdutabStore F-Droid Server"
    echo "=========================="
    echo ""
    echo "Commands:"
    echo "  init        - Initialize a new repository"
    echo "  update      - Update repository index (run after adding APKs)"
    echo "  sign        - Sign APKs in the unsigned folder"
    echo "  fingerprint - Show repository fingerprint"
    echo "  certificate - Export certificate for client config"
    echo "  shell       - Start interactive shell"
    echo "  help        - Show this help message"
    echo ""
    echo "Volumes:"
    echo "  /repo       - Repository data (index, APKs)"
    echo "  /config     - Configuration and keystore (KEEP BACKED UP!)"
    echo "  /unsigned   - Drop APKs here for automatic import"
    echo ""
    echo "Example workflow:"
    echo "  1. docker-compose run fdroid init"
    echo "  2. Edit /config/config.yml with your settings"
    echo "  3. Copy APKs to the unsigned/ folder"
    echo "  4. docker-compose run fdroid update"
    echo "  5. docker-compose run fdroid certificate"
    echo "  6. docker-compose up -d nginx"
    echo ""
}

case "$1" in
    init)
        init_repo
        ;;
    update)
        init_repo
        update_repo
        ;;
    sign)
        sign_apks
        ;;
    fingerprint)
        show_fingerprint
        ;;
    certificate)
        export_certificate
        ;;
    shell)
        exec /bin/bash
        ;;
    help|--help|-h|"")
        print_help
        ;;
    *)
        # Pass through any other fdroid commands
        cd "$REPO_DIR"
        exec fdroid "$@"
        ;;
esac
