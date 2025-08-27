#!/usr/bin/env python3
"""
Setup script for Python Honeypot IDS (PHIDS)
Automates the installation and configuration process
"""

import os
import sys
import subprocess
import platform
from pathlib import Path


def run_command(command, check=True):
    """Run a shell command and return the result."""
    try:
        result = subprocess.run(command, shell=True, check=check, 
                              capture_output=True, text=True)
        return result.returncode == 0, result.stdout, result.stderr
    except subprocess.CalledProcessError as e:
        return False, e.stdout, e.stderr


def check_python_version():
    """Check if Python version is 3.10 or higher."""
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 10):
        print(f"❌ Python 3.10+ required. Current version: {version.major}.{version.minor}")
        return False
    print(f"✅ Python version: {version.major}.{version.minor}.{version.micro}")
    return True


def create_virtual_environment():
    """Create a virtual environment if it doesn't exist."""
    venv_path = Path("venv")
    if venv_path.exists():
        print("✅ Virtual environment already exists")
        return True
    
    print("📦 Creating virtual environment...")
    success, stdout, stderr = run_command(f"{sys.executable} -m venv venv")
    if success:
        print("✅ Virtual environment created successfully")
        return True
    else:
        print(f"❌ Failed to create virtual environment: {stderr}")
        return False


def get_activation_command():
    """Get the appropriate activation command for the current OS."""
    if platform.system() == "Windows":
        return "venv\\Scripts\\activate"
    else:
        return "source venv/bin/activate"


def install_requirements():
    """Install project requirements."""
    print("📦 Installing requirements...")
    
    # Determine pip path based on OS
    if platform.system() == "Windows":
        pip_path = "venv\\Scripts\\pip"
    else:
        pip_path = "venv/bin/pip"
    
    # Upgrade pip first
    print("⬆️ Upgrading pip...")
    success, stdout, stderr = run_command(f"{pip_path} install --upgrade pip")
    if not success:
        print(f"⚠️ Warning: Failed to upgrade pip: {stderr}")
    
    # Install requirements
    success, stdout, stderr = run_command(f"{pip_path} install -r requirements.txt")
    if success:
        print("✅ Requirements installed successfully")
        return True
    else:
        print(f"❌ Failed to install requirements: {stderr}")
        return False


def create_directories():
    """Create necessary directories."""
    directories = ["logs", "data", "reports"]
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
    print("✅ Directory structure created")


def display_next_steps():
    """Display next steps for the user."""
    activation_cmd = get_activation_command()
    
    print("\n" + "="*60)
    print("🎉 PHIDS Setup Complete!")
    print("="*60)
    print("\n📋 Next Steps:")
    print(f"1. Activate virtual environment:")
    print(f"   {activation_cmd}")
    print("\n2. (Optional) Set API keys for threat intelligence:")
    print("   export VIRUSTOTAL_API_KEY='your_vt_api_key'")
    print("   export ABUSEIPDB_API_KEY='your_abuseipdb_api_key'")
    print("\n3. Run PHIDS:")
    print("   python main.py")
    print("\n4. Test the installation:")
    print("   python main.py --help")
    print("\n📚 For more information, see README.md")
    print("="*60)


def main():
    """Main setup function."""
    print("🚀 Python Honeypot IDS (PHIDS) Setup")
    print("="*40)
    
    # Check Python version
    if not check_python_version():
        sys.exit(1)
    
    # Create virtual environment
    if not create_virtual_environment():
        sys.exit(1)
    
    # Install requirements
    if not install_requirements():
        sys.exit(1)
    
    # Create directories
    create_directories()
    
    # Display next steps
    display_next_steps()


if __name__ == "__main__":
    main()
