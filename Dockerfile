# Mythic Mobile Agent Builder Container
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    openjdk-17-jdk \
    wget \
    unzip \
    build-essential \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set JAVA_HOME
ENV JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64

# Install Android SDK
ENV ANDROID_SDK_ROOT=/opt/android-sdk
ENV PATH=${PATH}:${ANDROID_SDK_ROOT}/cmdline-tools/latest/bin:${ANDROID_SDK_ROOT}/platform-tools

RUN mkdir -p ${ANDROID_SDK_ROOT}/cmdline-tools && \
    cd ${ANDROID_SDK_ROOT}/cmdline-tools && \
    wget https://dl.google.com/android/repository/commandlinetools-linux-10406996_latest.zip && \
    unzip commandlinetools-linux-10406996_latest.zip && \
    mv cmdline-tools latest && \
    rm commandlinetools-linux-10406996_latest.zip

# Accept Android SDK licenses and install components
RUN yes | sdkmanager --licenses && \
    sdkmanager "platform-tools" "platforms;android-33" "platforms;android-34" "build-tools;33.0.2" "build-tools;34.0.0" && \
    sdkmanager "ndk;25.2.9519653"

# Set NDK environment
ENV ANDROID_NDK_ROOT=${ANDROID_SDK_ROOT}/ndk/25.2.9519653
ENV PATH=${PATH}:${ANDROID_NDK_ROOT}

# Install APK manipulation tools
RUN wget https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.8.1.jar -O /opt/apktool.jar && \
    echo '#!/bin/bash\njava -jar /opt/apktool.jar "$@"' > /usr/local/bin/apktool && \
    chmod +x /usr/local/bin/apktool

# Install additional build tools
# Install baksmali/smali
RUN wget https://github.com/JesusFreke/smali/releases/download/v2.5.2/baksmali-2.5.2.jar -O /opt/baksmali.jar && \
    wget https://github.com/JesusFreke/smali/releases/download/v2.5.2/smali-2.5.2.jar -O /opt/smali.jar && \
    echo '#!/bin/bash\njava -jar /opt/baksmali.jar "$@"' > /usr/local/bin/baksmali && \
    echo '#!/bin/bash\njava -jar /opt/smali.jar "$@"' > /usr/local/bin/smali && \
    chmod +x /usr/local/bin/baksmali /usr/local/bin/smali

# Install ProGuard
RUN wget https://github.com/Guardsquare/proguard/releases/download/v7.3.2/proguard-7.3.2.zip -O /tmp/proguard.zip && \
    unzip /tmp/proguard.zip -d /opt/ && \
    mv /opt/proguard-7.3.2 /opt/proguard && \
    rm /tmp/proguard.zip && \
    echo '#!/bin/bash\njava -jar /opt/proguard/lib/proguard.jar "$@"' > /usr/local/bin/proguard && \
    chmod +x /usr/local/bin/proguard

# Install Python dependencies
COPY requirements.txt /tmp/
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Create working directory
WORKDIR /mythic_mobile_agent

# Copy source code
COPY . .

# Set permissions
RUN chmod +x builder/*.py

ENTRYPOINT ["python3", "builder/build_apk.py"]