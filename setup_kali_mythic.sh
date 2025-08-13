#!/bin/bash

# Eris Android Agent - Kali Linux Setup Script for Mythic Framework
# This script sets up Mythic framework on Kali Linux and installs the Eris agent

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Configuration
MYTHIC_DIR="/opt/mythic"
ERIS_AGENT_DIR="/opt/mythic/Agents/eris"
MYTHIC_VERSION="3.3.0"
DOCKER_COMPOSE_VERSION="2.21.0"

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${PURPLE}========================================${NC}"
    echo -e "${WHITE}$1${NC}"
    echo -e "${PURPLE}========================================${NC}"
}

# Function to check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        print_error "This script should not be run as root for security reasons."
        print_status "Please run as a regular user with sudo privileges."
        exit 1
    fi
}

# Function to check if running on Kali Linux
check_kali() {
    if ! grep -q "kali" /etc/os-release 2>/dev/null; then
        print_warning "This script is designed for Kali Linux."
        print_status "Detected OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)"
        read -p "Do you want to continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    else
        print_success "Kali Linux detected"
    fi
}

# Function to update system packages
update_system() {
    print_header "UPDATING SYSTEM PACKAGES"
    
    print_status "Updating package lists..."
    sudo apt update -y
    
    print_status "Upgrading installed packages..."
    sudo apt upgrade -y
    
    print_success "System updated successfully"
}

# Function to install prerequisites
install_prerequisites() {
    print_header "INSTALLING PREREQUISITES"
    
    local packages=(
        "curl"
        "wget"
        "git"
        "build-essential"
        "python3"
        "python3-pip"
        "python3-venv"
        "nodejs"
        "npm"
        "docker.io"
        "docker-compose"
        "jq"
        "unzip"
        "zip"
        "openssl"
        "ca-certificates"
        "gnupg"
        "lsb-release"
        "software-properties-common"
        "apt-transport-https"
    )
    
    print_status "Installing required packages..."
    for package in "${packages[@]}"; do
        print_status "Installing $package..."
        sudo apt install -y "$package"
    done
    
    print_success "Prerequisites installed successfully"
}

# Function to install Docker (latest version)
install_docker() {
    print_header "INSTALLING DOCKER"
    
    # Remove old versions
    print_status "Removing old Docker versions..."
    sudo apt remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true
    
    # Add Docker's official GPG key
    print_status "Adding Docker GPG key..."
    sudo mkdir -p /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    
    # Add Docker repository
    print_status "Adding Docker repository..."
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian bullseye stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
    
    # Update package index
    sudo apt update -y
    
    # Install Docker Engine
    print_status "Installing Docker Engine..."
    sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    
    # Add user to docker group
    print_status "Adding user to docker group..."
    sudo usermod -aG docker $USER
    
    # Enable and start Docker service
    print_status "Enabling Docker service..."
    sudo systemctl enable docker
    sudo systemctl start docker
    
    print_success "Docker installed successfully"
}

# Function to install Docker Compose (standalone)
install_docker_compose() {
    print_header "INSTALLING DOCKER COMPOSE"
    
    print_status "Downloading Docker Compose v${DOCKER_COMPOSE_VERSION}..."
    sudo curl -L "https://github.com/docker/compose/releases/download/v${DOCKER_COMPOSE_VERSION}/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    
    print_status "Making Docker Compose executable..."
    sudo chmod +x /usr/local/bin/docker-compose
    
    # Verify installation
    if docker-compose --version >/dev/null 2>&1; then
        print_success "Docker Compose installed successfully"
        print_status "Version: $(docker-compose --version)"
    else
        print_error "Docker Compose installation failed"
        exit 1
    fi
}

# Function to install Mythic CLI
install_mythic_cli() {
    print_header "INSTALLING MYTHIC CLI"
    
    print_status "Downloading Mythic CLI..."
    sudo curl -L "https://github.com/its-a-feature/Mythic/releases/latest/download/mythic-cli-linux-amd64" -o /usr/local/bin/mythic-cli
    
    print_status "Making Mythic CLI executable..."
    sudo chmod +x /usr/local/bin/mythic-cli
    
    # Verify installation
    if mythic-cli --help >/dev/null 2>&1; then
        print_success "Mythic CLI installed successfully"
    else
        print_error "Mythic CLI installation failed"
        exit 1
    fi
}

# Function to create Mythic directory structure
create_mythic_directories() {
    print_header "CREATING MYTHIC DIRECTORIES"
    
    print_status "Creating Mythic directory structure..."
    sudo mkdir -p "$MYTHIC_DIR"
    sudo mkdir -p "$MYTHIC_DIR/Agents"
    sudo mkdir -p "$MYTHIC_DIR/C2_Profiles"
    sudo mkdir -p "$MYTHIC_DIR/Payload_Types"
    sudo mkdir -p "$MYTHIC_DIR/logs"
    sudo mkdir -p "$MYTHIC_DIR/database_backups"
    
    print_status "Setting directory permissions..."
    sudo chown -R $USER:$USER "$MYTHIC_DIR"
    sudo chmod -R 755 "$MYTHIC_DIR"
    
    print_success "Mythic directories created successfully"
}

# Function to install Mythic framework
install_mythic() {
    print_header "INSTALLING MYTHIC FRAMEWORK"
    
    cd "$MYTHIC_DIR"
    
    print_status "Cloning Mythic repository..."
    git clone https://github.com/its-a-feature/Mythic.git .
    
    print_status "Checking out Mythic v${MYTHIC_VERSION}..."
    git checkout "v${MYTHIC_VERSION}" 2>/dev/null || git checkout "main"
    
    print_status "Making Mythic CLI executable..."
    chmod +x ./mythic-cli
    
    print_status "Installing Mythic dependencies..."
    ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
    ./mythic-cli install github https://github.com/MythicC2Profiles/http.git
    ./mythic-cli install github https://github.com/MythicC2Profiles/websocket.git
    
    print_success "Mythic framework installed successfully"
}

# Function to install Eris agent
install_eris_agent() {
    print_header "INSTALLING ERIS ANDROID AGENT"
    
    print_status "Creating Eris agent directory..."
    mkdir -p "$ERIS_AGENT_DIR"
    
    # Copy current agent files to Mythic directory
    if [[ -d "$(pwd)" ]] && [[ "$(basename $(pwd))" == "mythic_android_agent" ]]; then
        print_status "Copying Eris agent files..."
        cp -r ./* "$ERIS_AGENT_DIR/"
    else
        print_status "Cloning Eris agent repository..."
        git clone https://github.com/yourusername/eris-android-agent.git "$ERIS_AGENT_DIR"
    fi
    
    cd "$ERIS_AGENT_DIR"
    
    print_status "Setting up Python virtual environment..."
    python3 -m venv venv
    source venv/bin/activate
    
    print_status "Installing Python dependencies..."
    if [[ -f "requirements.txt" ]]; then
        pip install -r requirements.txt
    fi
    
    print_status "Installing additional Android tools..."
    # Install apktool
    wget https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool -O apktool
    wget https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.8.1.jar -O apktool.jar
    sudo mv apktool apktool.jar /usr/local/bin/
    sudo chmod +x /usr/local/bin/apktool
    
    # Install Android SDK tools
    print_status "Installing Android SDK tools..."
    mkdir -p ~/android-sdk
    cd ~/android-sdk
    wget https://dl.google.com/android/repository/commandlinetools-linux-9477386_latest.zip
    unzip commandlinetools-linux-9477386_latest.zip
    mkdir -p cmdline-tools/latest
    mv cmdline-tools/* cmdline-tools/latest/ 2>/dev/null || true
    
    # Set Android environment variables
    echo 'export ANDROID_HOME=~/android-sdk' >> ~/.bashrc
    echo 'export PATH=$PATH:$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools' >> ~/.bashrc
    
    cd "$ERIS_AGENT_DIR"
    
    print_success "Eris agent installed successfully"
}

# Function to configure Mythic
configure_mythic() {
    print_header "CONFIGURING MYTHIC"
    
    cd "$MYTHIC_DIR"
    
    print_status "Generating Mythic configuration..."
    ./mythic-cli config
    
    print_status "Setting up environment variables..."
    cat > .env << EOF
COMPOSE_PROJECT_NAME=mythic
MYTHIC_ADMIN_USER=admin
MYTHIC_ADMIN_PASSWORD=$(openssl rand -base64 32)
MYTHIC_SERVER_PORT=7443
MYTHIC_SERVER_BIND_LOCALHOST_ONLY=false
RABBITMQ_HOST=mythic_rabbitmq
POSTGRES_HOST=mythic_postgres
POSTGRES_USER=mythic_user
POSTGRES_PASSWORD=$(openssl rand -base64 32)
POSTGRES_DB=mythic_db
RABBITMQ_USER=mythic_user
RABBITMQ_PASSWORD=$(openssl rand -base64 32)
RABBITMQ_VHOST=mythic_vhost
NGINX_PORT=7443
JWT_SECRET=$(openssl rand -base64 64)
EOF
    
    print_status "Installing Eris agent in Mythic..."
    ./mythic-cli install folder "$ERIS_AGENT_DIR"
    
    print_success "Mythic configuration completed"
}

# Function to install C2 profiles for Eris
install_c2_profiles() {
    print_header "INSTALLING C2 PROFILES FOR ERIS"
    
    cd "$MYTHIC_DIR"
    
    # Install HTTP profile
    print_status "Installing HTTP C2 profile..."
    if [[ ! -d "C2_Profiles/http" ]]; then
        ./mythic-cli install github https://github.com/MythicC2Profiles/http.git
    fi
    
    # Install WebSocket profile
    print_status "Installing WebSocket C2 profile..."
    if [[ ! -d "C2_Profiles/websocket" ]]; then
        ./mythic-cli install github https://github.com/MythicC2Profiles/websocket.git
    fi
    
    # Copy Eris custom C2 profiles
    if [[ -d "$ERIS_AGENT_DIR/c2_profiles" ]]; then
        print_status "Installing Eris custom C2 profiles..."
        cp -r "$ERIS_AGENT_DIR/c2_profiles/"* "C2_Profiles/"
    fi
    
    print_success "C2 profiles installed successfully"
}

# Function to build and start Mythic
start_mythic() {
    print_header "STARTING MYTHIC FRAMEWORK"
    
    cd "$MYTHIC_DIR"
    
    print_status "Building Mythic containers..."
    ./mythic-cli build
    
    print_status "Starting Mythic services..."
    ./mythic-cli start
    
    print_status "Waiting for services to be ready..."
    sleep 30
    
    # Get admin credentials
    ADMIN_PASSWORD=$(grep MYTHIC_ADMIN_PASSWORD .env | cut -d'=' -f2)
    
    print_success "Mythic framework started successfully!"
    print_success "Access Mythic at: https://localhost:7443"
    print_success "Username: admin"
    print_success "Password: $ADMIN_PASSWORD"
}

# Function to create useful aliases and shortcuts
create_shortcuts() {
    print_header "CREATING SHORTCUTS AND ALIASES"
    
    # Add useful aliases to bashrc
    cat >> ~/.bashrc << 'EOF'

# Eris/Mythic aliases
alias mythic-start='cd /opt/mythic && ./mythic-cli start'
alias mythic-stop='cd /opt/mythic && ./mythic-cli stop'
alias mythic-restart='cd /opt/mythic && ./mythic-cli restart'
alias mythic-logs='cd /opt/mythic && ./mythic-cli logs'
alias mythic-status='cd /opt/mythic && ./mythic-cli status'
alias eris-cd='cd /opt/mythic/Agents/eris'
alias eris-test='cd /opt/mythic/Agents/eris && python -m pytest test/'
alias eris-build='cd /opt/mythic/Agents/eris && python builder/build_apk.py'
EOF
    
    # Create desktop shortcut
    mkdir -p ~/Desktop
    cat > ~/Desktop/mythic-framework.desktop << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=Mythic Framework
Comment=Open Mythic Framework Web Interface
Exec=firefox https://localhost:7443
Icon=applications-internet
Terminal=false
Categories=Network;Security;
EOF
    chmod +x ~/Desktop/mythic-framework.desktop
    
    print_success "Shortcuts and aliases created successfully"
}

# Function to setup firewall rules
setup_firewall() {
    print_header "CONFIGURING FIREWALL"
    
    print_status "Configuring UFW firewall rules..."
    
    # Enable UFW
    sudo ufw --force enable
    
    # Allow SSH
    sudo ufw allow 22/tcp
    
    # Allow Mythic web interface
    sudo ufw allow 7443/tcp
    
    # Allow Docker containers
    sudo ufw allow 5432/tcp  # PostgreSQL
    sudo ufw allow 5672/tcp  # RabbitMQ
    sudo ufw allow 15672/tcp # RabbitMQ Management
    
    # Allow common C2 ports
    sudo ufw allow 80/tcp
    sudo ufw allow 443/tcp
    sudo ufw allow 8080/tcp
    sudo ufw allow 8443/tcp
    
    print_success "Firewall configured successfully"
}

# Function to create systemd service for Mythic
create_systemd_service() {
    print_header "CREATING SYSTEMD SERVICE"
    
    print_status "Creating Mythic systemd service..."
    sudo tee /etc/systemd/system/mythic.service > /dev/null <<EOF
[Unit]
Description=Mythic Framework
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=true
WorkingDirectory=/opt/mythic
ExecStart=/opt/mythic/mythic-cli start
ExecStop=/opt/mythic/mythic-cli stop
User=$USER
Group=docker

[Install]
WantedBy=multi-user.target
EOF
    
    print_status "Enabling Mythic service..."
    sudo systemctl daemon-reload
    sudo systemctl enable mythic.service
    
    print_success "Systemd service created successfully"
}

# Function to run post-installation tests
run_tests() {
    print_header "RUNNING POST-INSTALLATION TESTS"
    
    # Test Docker
    print_status "Testing Docker installation..."
    if docker --version >/dev/null 2>&1; then
        print_success "Docker: OK"
    else
        print_error "Docker: FAILED"
    fi
    
    # Test Docker Compose
    print_status "Testing Docker Compose installation..."
    if docker-compose --version >/dev/null 2>&1; then
        print_success "Docker Compose: OK"
    else
        print_error "Docker Compose: FAILED"
    fi
    
    # Test Mythic CLI
    print_status "Testing Mythic CLI..."
    if mythic-cli --help >/dev/null 2>&1; then
        print_success "Mythic CLI: OK"
    else
        print_error "Mythic CLI: FAILED"
    fi
    
    # Test Eris agent
    print_status "Testing Eris agent installation..."
    if [[ -d "$ERIS_AGENT_DIR" ]] && [[ -f "$ERIS_AGENT_DIR/mythic_integration.py" ]]; then
        print_success "Eris Agent: OK"
    else
        print_error "Eris Agent: FAILED"
    fi
    
    # Test Mythic services
    print_status "Testing Mythic services..."
    cd "$MYTHIC_DIR"
    if ./mythic-cli status | grep -q "mythic_server.*Up"; then
        print_success "Mythic Services: OK"
    else
        print_warning "Mythic Services: Some services may be starting"
    fi
}

# Function to display final instructions
show_final_instructions() {
    print_header "INSTALLATION COMPLETE!"
    
    echo -e "${GREEN}Eris Android Agent and Mythic Framework have been successfully installed!${NC}"
    echo
    echo -e "${CYAN}Access Information:${NC}"
    echo -e "  Web Interface: ${WHITE}https://localhost:7443${NC}"
    echo -e "  Username: ${WHITE}admin${NC}"
    echo -e "  Password: ${WHITE}$(grep MYTHIC_ADMIN_PASSWORD $MYTHIC_DIR/.env | cut -d'=' -f2)${NC}"
    echo
    echo -e "${CYAN}Useful Commands:${NC}"
    echo -e "  Start Mythic:   ${WHITE}mythic-start${NC}"
    echo -e "  Stop Mythic:    ${WHITE}mythic-stop${NC}"
    echo -e "  View Logs:      ${WHITE}mythic-logs${NC}"
    echo -e "  Check Status:   ${WHITE}mythic-status${NC}"
    echo -e "  Go to Eris:     ${WHITE}eris-cd${NC}"
    echo -e "  Test Eris:      ${WHITE}eris-test${NC}"
    echo
    echo -e "${CYAN}Directories:${NC}"
    echo -e "  Mythic:         ${WHITE}$MYTHIC_DIR${NC}"
    echo -e "  Eris Agent:     ${WHITE}$ERIS_AGENT_DIR${NC}"
    echo
    echo -e "${YELLOW}Next Steps:${NC}"
    echo "1. Source your bashrc to load aliases: source ~/.bashrc"
    echo "2. Access the web interface and familiarize yourself with Mythic"
    echo "3. Build your first Eris payload using the agent builder"
    echo "4. Configure C2 profiles for your operations"
    echo "5. Review the Eris documentation for advanced features"
    echo
    echo -e "${RED}Security Reminders:${NC}"
    echo "- Change the default admin password"
    echo "- Configure SSL certificates for production use"
    echo "- Review firewall rules for your environment"
    echo "- Regularly backup your Mythic database"
    echo
    echo -e "${GREEN}Happy hunting! 🎯${NC}"
}

# Main installation function
main() {
    print_header "ERIS ANDROID AGENT - KALI LINUX SETUP"
    
    # Pre-installation checks
    check_root
    check_kali
    
    # Installation steps
    update_system
    install_prerequisites
    install_docker
    install_docker_compose
    install_mythic_cli
    create_mythic_directories
    install_mythic
    install_eris_agent
    configure_mythic
    install_c2_profiles
    start_mythic
    create_shortcuts
    setup_firewall
    create_systemd_service
    
    # Post-installation
    run_tests
    show_final_instructions
}

# Error handling
trap 'print_error "Installation failed at line $LINENO. Check the logs above for details."' ERR

# Run main function
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
