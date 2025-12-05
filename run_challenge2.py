#!/usr/bin/env python3
"""
Challenge 2 Test Selector
=========================

Script para escolher entre teste Mock ou Produção Azure
"""

import sys
import subprocess

def print_header():
    print("\n" + "="*70)
    print("🔴 CHALLENGE 2: WAF & SECURE FOUNDATION - TEST SELECTOR")
    print("="*70)
    print("Choose your testing approach:")
    print()

def print_options():
    print("📋 AVAILABLE OPTIONS:")
    print()
    print("1. 🎭 MOCK TEST")
    print("   • Fast and free")
    print("   • No Azure setup required") 
    print("   • Uses simulated data")
    print("   • Good for development/CI")
    print("   • Command: python test_challenge2_mock.py")
    print()
    print("2. 🏭 PRODUCTION TEST (Azure)")
    print("   • Real Azure resources")
    print("   • Requires Azure setup")
    print("   • Generates real costs (~$500-800/month)")
    print("   • Enterprise validation")
    print("   • Command: python test_challenge2.py")
    print()
    print("3. 🔍 VALIDATE AZURE SETUP")
    print("   • Check Azure configuration")
    print("   • Validate credentials and resources")
    print("   • Command: python validate_azure_production.py")
    print()
    print("4. 📚 SETUP GUIDE")
    print("   • View Azure setup instructions")
    print("   • See AZURE_PRODUCTION_SETUP.md")
    print()

def run_command(command):
    """Execute command"""
    print(f"\n🚀 Running: {command}")
    print("-" * 50)
    try:
        result = subprocess.run(command.split(), check=False)
        return result.returncode
    except Exception as e:
        print(f"❌ Error executing command: {e}")
        return 1

def main():
    print_header()
    print_options()
    
    try:
        choice = input("Enter your choice (1-4) or 'q' to quit: ").strip()
        
        if choice == 'q':
            print("\n👋 Goodbye!")
            return 0
            
        elif choice == '1':
            print("\n🎭 Starting MOCK Test...")
            return run_command("python test_challenge2_mock.py")
            
        elif choice == '2':
            print("\n🏭 Starting PRODUCTION Test...")
            print("⚠️  This will use real Azure resources and generate costs!")
            confirm = input("Continue? (y/N): ").strip().lower()
            if confirm == 'y':
                return run_command("python test_challenge2.py")
            else:
                print("❌ Production test cancelled")
                return 0
                
        elif choice == '3':
            print("\n🔍 Validating Azure Setup...")
            return run_command("python validate_azure_production.py")
            
        elif choice == '4':
            print("\n📚 Azure Setup Guide:")
            print("-" * 30)
            try:
                with open('AZURE_PRODUCTION_SETUP.md', 'r') as f:
                    lines = f.readlines()[:50]  # First 50 lines
                    for line in lines:
                        print(line.rstrip())
                print("\n... (see full file: AZURE_PRODUCTION_SETUP.md)")
            except FileNotFoundError:
                print("❌ Setup guide not found. Check AZURE_PRODUCTION_SETUP.md")
            return 0
            
        else:
            print(f"❌ Invalid choice: {choice}")
            return 1
            
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
        return 0
    except Exception as e:
        print(f"❌ Error: {e}")
        return 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)