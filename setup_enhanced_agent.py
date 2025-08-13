#!/usr/bin/env python3
"""
Enhanced Mythic Android Agent Setup Script
Comprehensive installation with Frida, ProGuard, and Shell Interface
"""

import os
import sys
import json
import shutil
import subprocess
import platform
from pathlib import Path
from typing import Dict, List

class EnhancedAgentSetup:
    def __init__(self):
        self.agent_dir = Path(__file__).parent
        self.deps_dir = self.agent_dir / "dependencies"
        self.shell_dir = self.agent_dir / "shell_interface"
        self.platform = platform.system().lower()
        self.architecture = platform.machine().lower()
        
        # Configuration
        self.config = {
            "frida_version": "16.1.4",
            "proguard_version": "7.4.0",
            "android_archs": ["arm64", "arm", "x86_64", "x86"]
        }
        
        print("🚀 Enhanced Mythic Android Agent Setup")
        print(f"📁 Agent Directory: {self.agent_dir}")
        print(f"💻 Platform: {self.platform} ({self.architecture})")
        print("=" * 60)
    
    def setup_all(self):
        """Complete setup process"""
        try:
            print("🔧 Starting comprehensive setup...")
            
            # Create directory structure
            self.create_directory_structure()
            
            # Install Python dependencies
            self.install_python_dependencies()
            
            # Download and setup Frida
            self.setup_frida()
            
            # Download and setup ProGuard
            self.setup_proguard()
            
            # Setup enhanced build system
            self.setup_build_system()
            
            # Setup shell interface
            self.setup_shell_interface()
            
            # Create initial assets
            self.create_initial_assets()
            
            # Validate installation
            self.validate_installation()
            
            print("✅ Enhanced Mythic Android Agent setup completed successfully!")
            print("\n📋 Next steps:")
            print("1. Configure your C2 server details in build_config.json")
            print("2. Set ANDROID_HOME environment variable")
            print("3. Run: make all")
            print("4. Deploy the generated APK")
            
        except Exception as e:
            print(f"❌ Setup failed: {e}")
            sys.exit(1)
    
    def create_directory_structure(self):
        """Create required directory structure"""
        print("📁 Creating directory structure...")
        
        directories = [
            "dependencies/frida",
            "dependencies/proguard", 
            "dependencies/frida-server",
            "assets/frida-agents/servers",
            "assets/frida-agents/scripts",
            "assets/frida-agents/utils",
            "shell_interface",
            "build/temp",
            "build/output",
            "tests"
        ]
        
        for dir_path in directories:
            full_path = self.agent_dir / dir_path
            full_path.mkdir(parents=True, exist_ok=True)
            print(f"  ✓ Created: {dir_path}")
    
    def install_python_dependencies(self):
        """Install Python dependencies"""
        print("📦 Installing Python dependencies...")
        
        requirements_file = self.agent_dir / "requirements.txt"
        if not requirements_file.exists():
            print("❌ requirements.txt not found")
            return
        
        try:
            cmd = [sys.executable, "-m", "pip", "install", "-r", str(requirements_file)]
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            print("  ✓ Python dependencies installed successfully")
        except subprocess.CalledProcessError as e:
            print(f"  ⚠️  Some dependencies failed to install: {e.stderr}")
            print("  → Continuing with setup...")
    
    def setup_frida(self):
        """Download and setup Frida"""
        print("🔥 Setting up Frida...")
        
        # Install Frida Python tools
        try:
            cmd = [sys.executable, "-m", "pip", "install", f"frida-tools=={self.config['frida_version']}"]
            subprocess.run(cmd, check=True, capture_output=True)
            print("  ✓ Frida Python tools installed")
        except subprocess.CalledProcessError:
            print("  ⚠️  Frida Python tools installation failed")
        
        # Download Frida servers for Android
        self.download_frida_servers()
        
        print("  ✓ Frida setup completed")
    
    def download_frida_servers(self):
        """Download Frida server binaries for Android architectures"""
        print("  📱 Downloading Frida servers for Android...")
        
        import urllib.request
        import lzma
        
        frida_server_dir = self.deps_dir / "frida-server"
        
        for arch in self.config['android_archs']:
            filename = f"frida-server-{self.config['frida_version']}-android-{arch}"
            url = f"https://github.com/frida/frida/releases/download/{self.config['frida_version']}/{filename}.xz"
            
            try:
                print(f"    📥 Downloading {arch}...")
                
                # Download compressed file
                compressed_path = frida_server_dir / f"{filename}.xz"
                urllib.request.urlretrieve(url, compressed_path)
                
                # Decompress
                decompressed_path = frida_server_dir / filename
                with lzma.open(compressed_path, 'rb') as compressed_file:
                    with open(decompressed_path, 'wb') as decompressed_file:
                        decompressed_file.write(compressed_file.read())
                
                # Make executable
                os.chmod(decompressed_path, 0o755)
                
                # Clean up compressed file
                compressed_path.unlink()
                
                print(f"    ✓ Downloaded and extracted {arch}")
                
            except Exception as e:
                print(f"    ⚠️  Failed to download {arch}: {e}")
    
    def setup_proguard(self):
        """Download and setup ProGuard"""
        print("🛡️  Setting up ProGuard...")
        
        import urllib.request
        import zipfile
        
        proguard_dir = self.deps_dir / "proguard"
        proguard_version = self.config['proguard_version']
        
        try:
            # Download ProGuard
            zip_filename = f"proguard-{proguard_version}.zip"
            zip_path = proguard_dir / zip_filename
            url = f"https://github.com/Guardsquare/proguard/releases/download/v{proguard_version}/{zip_filename}"
            
            print(f"  📥 Downloading ProGuard {proguard_version}...")
            urllib.request.urlretrieve(url, zip_path)
            
            # Extract
            print("  📦 Extracting ProGuard...")
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(proguard_dir)
            
            # Make scripts executable
            proguard_script_dir = proguard_dir / f"proguard-{proguard_version}" / "bin"
            if proguard_script_dir.exists():
                for script in proguard_script_dir.glob("*"):
                    if script.is_file() and not script.suffix:
                        os.chmod(script, 0o755)
            
            # Clean up zip file
            zip_path.unlink()
            
            print("  ✓ ProGuard setup completed")
            
        except Exception as e:
            print(f"  ⚠️  ProGuard setup failed: {e}")
    
    def setup_build_system(self):
        """Setup enhanced build system"""
        print("🏗️  Setting up enhanced build system...")
        
        # Ensure build scripts are executable
        build_scripts = [
            "builder/enhanced_build.py",
            "builder/create_frida_assets.py",
            "builder/build_apk.py"
        ]
        
        for script_path in build_scripts:
            script = self.agent_dir / script_path
            if script.exists():
                os.chmod(script, 0o755)
                print(f"  ✓ Made executable: {script_path}")
        
        # Create build configuration if it doesn't exist
        config_file = self.agent_dir / "build_config.json"
        if config_file.exists():
            print("  ✓ Build configuration found")
        else:
            print("  ⚠️  build_config.json not found - using default configuration")
    
    def setup_shell_interface(self):
        """Setup extensible shell interface"""
        print("🐚 Setting up extensible shell interface...")
        
        shell_script = self.shell_dir / "extensible_shell.py"
        if shell_script.exists():
            os.chmod(shell_script, 0o755)
            print("  ✓ Shell interface ready")
        else:
            print("  ⚠️  Shell interface not found")
        
        # Create shell configuration
        shell_config = {
            "server": {
                "host": "127.0.0.1",
                "port": 8765
            },
            "features": {
                "multi_sessions": True,
                "frida_integration": True,
                "command_history": True,
                "auto_completion": True
            }
        }
        
        config_path = self.shell_dir / "shell_config.json"
        with open(config_path, 'w') as f:
            json.dump(shell_config, f, indent=2)
        
        print("  ✓ Shell configuration created")
    
    def create_initial_assets(self):
        """Create initial Frida assets"""
        print("🎯 Creating initial assets...")
        
        try:
            # Run the Frida asset creator
            asset_creator = self.agent_dir / "builder" / "create_frida_assets.py"
            if asset_creator.exists():
                subprocess.run([sys.executable, str(asset_creator)], check=True)
                print("  ✓ Frida assets created")
            else:
                print("  ⚠️  Frida asset creator not found")
        except subprocess.CalledProcessError as e:
            print(f"  ⚠️  Failed to create initial assets: {e}")
    
    def validate_installation(self):
        """Validate the installation"""
        print("🔍 Validating installation...")
        
        validations = [
            ("Frida CLI", self.check_frida_cli),
            ("ProGuard", self.check_proguard),
            ("Android SDK", self.check_android_sdk),
            ("Build System", self.check_build_system),
            ("Shell Interface", self.check_shell_interface)
        ]
        
        for name, check_func in validations:
            try:
                if check_func():
                    print(f"  ✓ {name}: OK")
                else:
                    print(f"  ⚠️  {name}: Not found or incomplete")
            except Exception as e:
                print(f"  ❌ {name}: Error - {e}")
    
    def check_frida_cli(self) -> bool:
        """Check if Frida CLI is available"""
        try:
            result = subprocess.run(["frida", "--version"], capture_output=True, text=True)
            return result.returncode == 0
        except FileNotFoundError:
            return False
    
    def check_proguard(self) -> bool:
        """Check if ProGuard is available"""
        proguard_dir = self.deps_dir / "proguard" / f"proguard-{self.config['proguard_version']}"
        return proguard_dir.exists()
    
    def check_android_sdk(self) -> bool:
        """Check if Android SDK is available"""
        android_home = os.environ.get('ANDROID_HOME')
        if not android_home:
            return False
        
        sdk_path = Path(android_home)
        return sdk_path.exists() and (sdk_path / "platform-tools").exists()
    
    def check_build_system(self) -> bool:
        """Check if build system is ready"""
        required_files = [
            "builder/enhanced_build.py",
            "builder/create_frida_assets.py",
            "build_config.json"
        ]
        
        return all((self.agent_dir / f).exists() for f in required_files)
    
    def check_shell_interface(self) -> bool:
        """Check if shell interface is ready"""
        shell_script = self.shell_dir / "extensible_shell.py"
        return shell_script.exists()
    
    def create_makefile_wrapper(self):
        """Create platform-appropriate Makefile wrapper"""
        if self.platform == "windows":
            # Create batch wrapper for Windows
            wrapper_content = '''@echo off
REM Enhanced Mythic Android Agent Build Script for Windows

if "%1"=="all" (
    echo Installing dependencies and building...
    python -m pip install -r requirements.txt
    python builder/create_frida_assets.py
    python builder/enhanced_build.py build_config.json
    goto :eof
)

if "%1"=="install" (
    echo Installing dependencies...
    python setup_enhanced_agent.py
    goto :eof
)

if "%1"=="build" (
    echo Building APK...
    python builder/create_frida_assets.py
    python builder/enhanced_build.py build_config.json
    goto :eof
)

if "%1"=="shell" (
    echo Starting shell interface...
    python shell_interface/extensible_shell.py
    goto :eof
)

echo Available targets: all, install, build, shell
'''
            
            wrapper_path = self.agent_dir / "make.bat"
            with open(wrapper_path, 'w') as f:
                f.write(wrapper_content)
            
            print("  ✓ Created Windows build wrapper (make.bat)")

def main():
    """Main setup function"""
    print("🎯 Enhanced Mythic Android Agent Setup")
    print("=====================================")
    
    if len(sys.argv) > 1 and sys.argv[1] in ["--help", "-h"]:
        print("Usage: python setup_enhanced_agent.py")
        print("       python setup_enhanced_agent.py --validate-only")
        return
    
    setup = EnhancedAgentSetup()
    
    if len(sys.argv) > 1 and sys.argv[1] == "--validate-only":
        print("🔍 Running validation only...")
        setup.validate_installation()
    else:
        setup.setup_all()
    
    print("\n🎉 Setup completed! The Enhanced Mythic Android Agent is ready.")
    print("📖 Check the README.md for usage instructions.")

if __name__ == "__main__":
    main()
