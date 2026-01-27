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
    && rm -rf /var/lib/apt/lists/*

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

# Create fdroid user
RUN useradd -m -s /bin/bash fdroid

# Create repo directory structure
RUN mkdir -p /repo /config /unsigned && \
    chown -R fdroid:fdroid /repo /config /unsigned

# Copy entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

USER fdroid
WORKDIR /repo

# Volumes for persistent data
VOLUME ["/repo", "/config", "/unsigned"]

ENTRYPOINT ["/entrypoint.sh"]
CMD ["help"]
