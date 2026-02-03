FROM debian:bookworm-slim

LABEL maintainer="EdutabStore"
LABEL description="F-Droid Server for EdutabStore"

ENV DEBIAN_FRONTEND=noninteractive
ENV ANDROID_HOME=/opt/android-sdk
ENV PATH="${PATH}:${ANDROID_HOME}/cmdline-tools/latest/bin:${ANDROID_HOME}/platform-tools"

# Install dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    fdroidserver \
    python3 \
    python3-pip \
    python3-venv \
    openjdk-17-jdk-headless \
    wget \
    unzip \
    git \
    rsync \
    openssh-client \
    apksigner \
    androguard \
    nginx \
    supervisor \
    && rm -rf /var/lib/apt/lists/*

# Upgrade androguard to fix "res1 must be zero" error with newer APKs
RUN pip3 install --no-cache-dir --break-system-packages --upgrade androguard

# Install Android SDK command-line tools
RUN mkdir -p ${ANDROID_HOME}/cmdline-tools && \
    cd ${ANDROID_HOME}/cmdline-tools && \
    wget -q https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip -O tools.zip && \
    unzip -q tools.zip && \
    rm tools.zip && \
    mv cmdline-tools latest

# Accept Android SDK licenses and install build-tools
RUN yes | sdkmanager --licenses && \
    sdkmanager "platform-tools" "build-tools;34.0.0"

# Create symlink for bubblewrap compatibility (expects tools or bin in SDK root)
RUN ln -s ${ANDROID_HOME}/cmdline-tools/latest/bin ${ANDROID_HOME}/bin

# Install apkeep for APK downloads
RUN wget -q https://github.com/EFForg/apkeep/releases/download/0.18.0/apkeep-x86_64-unknown-linux-gnu -O /usr/local/bin/apkeep && \
    chmod +x /usr/local/bin/apkeep

# Install Node.js, Gradle, and expect for Bubblewrap
RUN apt-get update && apt-get install -y --no-install-recommends \
    nodejs \
    npm \
    gradle \
    expect \
    && rm -rf /var/lib/apt/lists/*

# Create .aspect directory for Bubblewrap config
RUN mkdir -p /root/.aspect && \
    chmod -R 755 /root/.aspect

# Pre-configure Bubblewrap with JDK and SDK paths to avoid interactive prompts
RUN echo '{"jdkPath":"/usr/lib/jvm/java-17-openjdk-amd64","androidSdkPath":"/opt/android-sdk"}' > /root/.aspect/aspect-config.json

# Pre-download Gradle wrapper (version used by Bubblewrap TWA template)
ENV GRADLE_USER_HOME=/root/.gradle
RUN mkdir -p ${GRADLE_USER_HOME}/wrapper/dists && \
    cd /tmp && \
    wget -q https://services.gradle.org/distributions/gradle-8.0-bin.zip && \
    mkdir -p ${GRADLE_USER_HOME}/wrapper/dists/gradle-8.0-bin && \
    unzip -q gradle-8.0-bin.zip -d ${GRADLE_USER_HOME}/wrapper/dists/gradle-8.0-bin/ && \
    rm gradle-8.0-bin.zip

# Create directories
RUN mkdir -p /data/repo /data/config /data/unsigned /data/virustotal /data/pwa-builds /var/log/supervisor && \
    chown -R www-data:www-data /data

# Copy admin API and install dependencies
COPY admin /opt/admin
RUN pip3 install --no-cache-dir --break-system-packages -r /opt/admin/requirements.txt && \
    cd /opt/admin && npm install && \
    chmod +x /opt/admin/pwa-builder.js

# Copy configuration files
COPY nginx.coolify.conf /etc/nginx/sites-available/default
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY entrypoint.sh /entrypoint.sh
COPY landing.html /data/landing.html
COPY repo-index.html /repo-index.html
COPY edutab-icon.png /edutab-icon.png
RUN chmod +x /entrypoint.sh

# Remove default nginx site
RUN rm -f /etc/nginx/sites-enabled/default && \
    ln -s /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default

WORKDIR /data/repo

EXPOSE 80

VOLUME ["/data"]

ENTRYPOINT ["/entrypoint.sh"]
CMD ["serve"]
