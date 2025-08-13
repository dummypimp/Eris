# Mythic Android Agent Enhanced Makefile
# Includes automatic Frida and ProGuard installation

SHELL := /bin/bash
PYTHON := python3
PIP := pip3
AGENT_DIR := $(CURDIR)
BUILD_DIR := $(AGENT_DIR)/build
DEPS_DIR := $(AGENT_DIR)/dependencies
FRIDA_VERSION := 16.1.4
PROGUARD_VERSION := 7.4.0

# Platform detection
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)
ifeq ($(OS),Windows_NT)
    PLATFORM := windows
    EXT := .exe
    FRIDA_SERVER_ARCH := x86_64
else ifeq ($(UNAME_S),Linux)
    PLATFORM := linux
    EXT := 
    ifeq ($(UNAME_M),x86_64)
        FRIDA_SERVER_ARCH := x86_64
    else ifeq ($(UNAME_M),aarch64)
        FRIDA_SERVER_ARCH := arm64
    endif
else ifeq ($(UNAME_S),Darwin)
    PLATFORM := macos
    EXT := 
    FRIDA_SERVER_ARCH := x86_64
endif

# Frida server architectures for Android
ANDROID_ARCHS := arm64 arm x86_64 x86

.PHONY: all install install-frida install-proguard install-android-tools setup-environment clean build test

all: install build

install: setup-environment install-python-deps install-frida install-proguard install-android-tools
	@echo "✅ Installation complete - Mythic Android Agent ready!"

setup-environment:
	@echo "🔧 Setting up environment..."
	@mkdir -p $(BUILD_DIR)
	@mkdir -p $(DEPS_DIR)
	@mkdir -p $(DEPS_DIR)/frida
	@mkdir -p $(DEPS_DIR)/proguard
	@mkdir -p $(DEPS_DIR)/frida-server
	@mkdir -p $(AGENT_DIR)/assets/frida-agents

install-python-deps:
	@echo "📦 Installing Python dependencies..."
	$(PIP) install --upgrade pip
	$(PIP) install frida-tools==$(FRIDA_VERSION)
	$(PIP) install frida==$(FRIDA_VERSION)
	$(PIP) install requests
	$(PIP) install cryptography
	$(PIP) install aiohttp
	$(PIP) install websockets
	@echo "✅ Python dependencies installed"

install-frida: install-python-deps download-frida-servers
	@echo "🔥 Installing Frida toolkit..."
	@if ! command -v frida &> /dev/null; then \
		echo "Installing Frida CLI tools..."; \
		$(PIP) install frida-tools==$(FRIDA_VERSION); \
	fi
	@echo "✅ Frida installation complete"

download-frida-servers:
	@echo "📱 Downloading Frida servers for Android..."
	@for arch in $(ANDROID_ARCHS); do \
		echo "Downloading frida-server for $$arch..."; \
		curl -L -o $(DEPS_DIR)/frida-server/frida-server-$(FRIDA_VERSION)-android-$$arch.xz \
			https://github.com/frida/frida/releases/download/$(FRIDA_VERSION)/frida-server-$(FRIDA_VERSION)-android-$$arch.xz || true; \
		if [ -f $(DEPS_DIR)/frida-server/frida-server-$(FRIDA_VERSION)-android-$$arch.xz ]; then \
			xz -d $(DEPS_DIR)/frida-server/frida-server-$(FRIDA_VERSION)-android-$$arch.xz; \
			chmod +x $(DEPS_DIR)/frida-server/frida-server-$(FRIDA_VERSION)-android-$$arch; \
		fi; \
	done
	@echo "✅ Frida servers downloaded"

install-proguard:
	@echo "🛡️  Installing ProGuard..."
	@if [ ! -d $(DEPS_DIR)/proguard/proguard-$(PROGUARD_VERSION) ]; then \
		echo "Downloading ProGuard $(PROGUARD_VERSION)..."; \
		curl -L -o $(DEPS_DIR)/proguard/proguard-$(PROGUARD_VERSION).zip \
			https://github.com/Guardsquare/proguard/releases/download/v$(PROGUARD_VERSION)/proguard-$(PROGUARD_VERSION).zip; \
		cd $(DEPS_DIR)/proguard && unzip -q proguard-$(PROGUARD_VERSION).zip; \
		chmod +x $(DEPS_DIR)/proguard/proguard-$(PROGUARD_VERSION)/bin/proguard.sh; \
		rm proguard-$(PROGUARD_VERSION).zip; \
	fi
	@echo "✅ ProGuard installation complete"

install-android-tools:
	@echo "🤖 Checking Android SDK tools..."
	@if [ -z "$$ANDROID_HOME" ]; then \
		echo "⚠️  ANDROID_HOME not set. Please install Android SDK and set ANDROID_HOME"; \
		echo "   Download from: https://developer.android.com/studio"; \
	else \
		echo "✅ Android SDK found at: $$ANDROID_HOME"; \
	fi

create-frida-agent-assets:
	@echo "🔥 Creating embedded Frida agent assets..."
	@$(PYTHON) $(AGENT_DIR)/builder/create_frida_assets.py
	@echo "✅ Frida agent assets created"

build: create-frida-agent-assets
	@echo "🏗️  Building Mythic Android Agent with embedded Frida..."
	@$(PYTHON) $(AGENT_DIR)/builder/enhanced_build.py
	@echo "✅ Build complete"

test:
	@echo "🧪 Running tests..."
	@$(PYTHON) -m pytest $(AGENT_DIR)/tests/ -v
	@echo "✅ Tests complete"

clean:
	@echo "🧹 Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)
	@rm -rf $(AGENT_DIR)/builder/__pycache__
	@rm -rf $(AGENT_DIR)/agent/__pycache__
	@rm -rf $(AGENT_DIR)/*.pyc
	@echo "✅ Clean complete"

clean-deps:
	@echo "🗑️  Cleaning dependencies..."
	@rm -rf $(DEPS_DIR)
	@echo "✅ Dependencies cleaned"

info:
	@echo "📋 Mythic Android Agent - Enhanced Build System"
	@echo "   Frida Version: $(FRIDA_VERSION)"
	@echo "   ProGuard Version: $(PROGUARD_VERSION)"
	@echo "   Platform: $(PLATFORM)"
	@echo "   Architecture: $(FRIDA_SERVER_ARCH)"
	@echo "   Dependencies Dir: $(DEPS_DIR)"
	@echo "   Build Dir: $(BUILD_DIR)"

help:
	@echo "📖 Available targets:"
	@echo "   all              - Full installation and build"
	@echo "   install          - Install all dependencies"
	@echo "   install-frida    - Install Frida toolkit"
	@echo "   install-proguard - Install ProGuard"
	@echo "   build            - Build APK with embedded Frida"
	@echo "   test             - Run tests"
	@echo "   clean            - Clean build artifacts"
	@echo "   clean-deps       - Clean downloaded dependencies"
	@echo "   info             - Show build information"
	@echo "   help             - Show this help"
