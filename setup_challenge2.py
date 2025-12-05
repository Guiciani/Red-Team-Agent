#!/usr/bin/env python3
"""
Challenge 2: Complete Setup Script
=================================

Script automatizado para configurar todo o ambiente do Challenge 2
"""

import os
import sys
import subprocess
import json
from pathlib import Path

def print_header(title: str):
    """Prints formatted header"""
    print("\\n" + "="*60)
    print(f"🚀 {title}")
    print("="*60)

def run_command(cmd: str, description: str) -> bool:
    """Executes command and returns success/failure"""
    print(f"\\n📦 {description}")
    print(f"   Command: {cmd}")
    
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            print("   ✅ Success")
            return True
        else:
            print(f"   ❌ Error: {result.stderr}")
            return False
    except Exception as e:
        print(f"   ❌ Exception: {e}")
        return False

def create_env_file():
    """Creates example .env file"""
    env_content = '''# Azure Credentials
AZURE_CLIENT_ID="your-client-id"
AZURE_CLIENT_SECRET="your-client-secret"
AZURE_TENANT_ID="your-tenant-id"
AZURE_SUBSCRIPTION_ID="your-subscription-id"

# Azure AI Services
AZURE_AI_SERVICES_KEY="your-ai-services-key"
AZURE_AI_SERVICES_ENDPOINT="https://your-ai-services.cognitiveservices.azure.com/"

# Azure AI Content Safety
AZURE_CONTENT_SAFETY_KEY="your-content-safety-key"
AZURE_CONTENT_SAFETY_ENDPOINT="https://your-content-safety.cognitiveservices.azure.com/"

# Azure OpenAI (optional)
AZURE_OPENAI_KEY="your-openai-key"
AZURE_OPENAI_ENDPOINT="https://your-openai.openai.azure.com/"
AZURE_OPENAI_DEPLOYMENT="gpt-4"

# Target Chatbot for Testing
CHATBOT_BASE_URL="http://localhost:8000"
CHATBOT_HEALTH_ENDPOINT="/health"

# Red Team Configuration
RED_TEAM_MAX_CONCURRENT=5
RED_TEAM_REQUEST_DELAY=1.0
RED_TEAM_TIMEOUT=30

# Logging Configuration
LOG_LEVEL="INFO"
LOG_FORMAT="json"
LOG_FILE="./logs/challenge2.log"
'''
    
    env_file = Path(".env")
    if not env_file.exists():
        env_file.write_text(env_content)
        print("✅ Created .env file")
    else:
        print("ℹ️ .env file already exists")

def create_directories():
    """Creates necessary directories"""
    directories = [
        "./reports",
        "./reports/challenge2", 
        "./logs",
        "./data",
        "./tests"
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        print(f"✅ Created directory: {directory}")

def install_python_dependencies():
    """Installs Python dependencies"""
    print_header("INSTALLING PYTHON DEPENDENCIES")
    
    # Upgrade pip primeiro
    success = run_command(
        f"{sys.executable} -m pip install --upgrade pip",
        "Upgrading pip"
    )
    
    if not success:
        print("⚠️ Failed to upgrade pip, continuing anyway...")
    
    # Instala requirements
    success = run_command(
        f"{sys.executable} -m pip install -r requirements.txt",
        "Installing requirements.txt"
    )
    
    return success

def verify_installation():
    """Verifies if installation was successful"""
    print_header("VERIFYING INSTALLATION")
    
    # Test imports
    test_imports = [
        "azure.identity",
        "azure.mgmt.resourcegraph", 
        "azure.ai.contentsafety",
        "aiohttp",
        "structlog",
        "pandas",
        "matplotlib"
    ]
    
    failed_imports = []
    
    for module in test_imports:
        try:
            __import__(module)
            print(f"✅ {module}")
        except ImportError:
            print(f"❌ {module}")
            failed_imports.append(module)
    
    if failed_imports:
        print(f"\\n⚠️ Failed imports: {', '.join(failed_imports)}")
        return False
    
    print("\\n✅ All core dependencies verified")
    return True

def run_test():
    """Runs basic test"""
    print_header("RUNNING BASIC TEST")
    
    success = run_command(
        f"{sys.executable} test_challenge2.py",
        "Running Challenge 2 test"
    )
    
    if success:
        print("\\n🎉 Challenge 2 test completed successfully!")
    else:
        print("\\n⚠️ Challenge 2 test failed - check configuration")
    
    return success

def display_next_steps():
    """Shows next steps"""
    print_header("NEXT STEPS")
    
    print("""
📋 CONFIGURATION NEEDED:

1. Edit .env file with your Azure credentials:
   - Azure service principal credentials
   - Azure AI Services keys and endpoints
   - Azure Content Safety endpoint

2. Ensure Azure resources are created:
   - Azure AI Services (for evaluation)
   - Azure AI Content Safety (for safety checks)
   - Service Principal with appropriate permissions

3. Run complete Challenge 2:
   python challenge2_complete.py

📚 DOCUMENTATION:

- README.md: General overview
- CHALLENGE2_README.md: Complete Challenge 2 guide
- requirements.txt: All dependencies listed

🧪 TESTING:

- test_challenge2.py: Mock test without Azure dependencies
- challenge2_complete.py: Full Challenge 2 implementation

🔧 TROUBLESHOOTING:

If you encounter issues:
1. Check .env configuration
2. Verify Azure permissions
3. Check network connectivity
4. Review logs in ./logs/challenge2.log

""")

def main():
    """Main setup function"""
    print_header("CHALLENGE 2 SETUP - Microsoft Secure AI Framework")
    
    print("""
This setup will configure everything needed for Challenge 2:
- Install Python dependencies
- Create configuration files
- Set up directory structure
- Run basic verification tests

Press Enter to continue or Ctrl+C to cancel...
""")
    
    try:
        input()
    except KeyboardInterrupt:
        print("\\n❌ Setup cancelled by user")
        sys.exit(1)
    
    # Step 1: Create directories
    print_header("CREATING DIRECTORIES")
    create_directories()
    
    # Step 2: Create .env file
    print_header("CREATING CONFIGURATION FILES")
    create_env_file()
    
    # Step 3: Install dependencies
    if not install_python_dependencies():
        print("❌ Failed to install dependencies")
        sys.exit(1)
    
    # Step 4: Verify installation
    if not verify_installation():
        print("❌ Installation verification failed")
        sys.exit(1)
    
    # Step 5: Run basic test
    run_test()
    
    # Step 6: Display next steps
    display_next_steps()
    
    print("\\n🎉 Challenge 2 setup completed successfully!")
    print("\\n📖 Next: Edit .env file and run 'python challenge2_complete.py'")

if __name__ == "__main__":
    main()