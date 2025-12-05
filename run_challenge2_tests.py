#!/usr/bin/env python3
"""
Challenge 2 Test Runner Selector - Azure Production
===================================================

Interactive selector for running different Challenge 2 test intensities
with real Azure integration.

Available Test Modes:
- Low Intensity (20%): Fast, cost-optimized for demos/POCs
- Moderate Intensity (50%): Balanced cost-coverage for regular validation  
- Full Intensity (100%): Comprehensive testing for certification
- Mock: Zero-cost development testing with simulated responses
"""

import asyncio
import subprocess
import sys
from pathlib import Path

def print_banner():
    """Print Challenge 2 banner"""
    print("\n" + "="*80)
    print("🔴 CHALLENGE 2: WAF & SECURE FOUNDATION - TEST RUNNER")
    print("="*80)
    print("Microsoft Secure AI Framework - Azure Production Integration")
    print("Choose your test intensity based on requirements and budget:")
    print("="*80)

def print_test_options():
    """Print available test options"""
    print("\n🎯 AVAILABLE TEST INTENSITIES:")
    print("-" * 50)
    
    print("1️⃣  LOW INTENSITY (20%)")
    print("    🚀 Fast • 💰 Low Cost • ⏱️ 2-4 minutes")
    print("    💵 ~$50-100/month • 🎯 Demos, POCs, Quick validation")
    print("    📊 50 attacks, 5 WAF checks, light evaluations")
    
    print("\n2️⃣  MODERATE INTENSITY (50%)")
    print("    ⚖️ Balanced • 💰 Moderate Cost • ⏱️ 5-10 minutes") 
    print("    💵 ~$200-400/month • 🎯 Regular validation, Integration testing")
    print("    📊 125 attacks, 11 WAF checks, moderate evaluations")
    
    print("\n3️⃣  FULL INTENSITY (100%)")
    print("    💎 Comprehensive • 💰 High Cost • ⏱️ 10-25 minutes")
    print("    💵 ~$500-800/month • 🎯 Certification, Production-ready validation")
    print("    📊 250+ attacks, 20+ WAF checks, full evaluations")
    
    print("\n4️⃣  MOCK TESTING (Development)")
    print("    🧪 Zero Cost • 💰 Free • ⏱️ 1-2 minutes")
    print("    💵 $0/month • 🎯 Development, CI/CD, Testing")
    print("    📊 Simulated responses, no Azure calls")
    
    print("\n0️⃣  EXIT")

async def run_selected_test(choice: str) -> int:
    """Run the selected test"""
    test_files = {
        "1": "test_challenge2_low_intensity.py",
        "2": "test_challenge2_moderate_intensity.py", 
        "3": "test_challenge2_full_intensity.py",
        "4": "test_challenge2_mock.py"
    }
    
    if choice not in test_files:
        print("❌ Invalid choice!")
        return 1
    
    test_file = test_files[choice]
    
    # Check if file exists
    if not Path(test_file).exists():
        print(f"❌ Test file not found: {test_file}")
        print("Please ensure all test files are present in the current directory")
        return 1
    
    # Print selected test info
    test_names = {
        "1": "LOW INTENSITY (20%)",
        "2": "MODERATE INTENSITY (50%)",
        "3": "FULL INTENSITY (100%)",
        "4": "MOCK TESTING"
    }
    
    print(f"\n🚀 Starting {test_names[choice]} test...")
    print(f"📁 Running: python {test_file}")
    print("⏳ Please wait while the test executes...\n")
    
    try:
        # Run the selected test
        result = subprocess.run([sys.executable, test_file], 
                              capture_output=False, 
                              text=True)
        return result.returncode
        
    except KeyboardInterrupt:
        print("\n❌ Test interrupted by user")
        return 1
    except Exception as e:
        print(f"❌ Error running test: {e}")
        return 1

def print_usage_recommendations():
    """Print usage recommendations"""
    print("\n💡 USAGE RECOMMENDATIONS:")
    print("-" * 50)
    print("🎯 For Demos/POCs: Choose Low Intensity (fast and cheap)")
    print("⚖️ For Regular Validation: Choose Moderate Intensity (balanced)")
    print("💎 For Production Certification: Choose Full Intensity (comprehensive)")
    print("🧪 For Development/Testing: Choose Mock Testing (free)")
    
    print("\n📋 PREREQUISITES:")
    print("-" * 50)
    print("✅ Azure subscription with AI Services deployed")
    print("✅ Environment variables configured (.env file)")
    print("✅ Azure CLI authentication: az login")
    print("✅ Required Python packages: pip install -r requirements.txt")
    print("✅ (Mock testing requires no Azure setup)")

async def main():
    """Main interactive test selector"""
    print_banner()
    print_test_options()
    print_usage_recommendations()
    
    while True:
        try:
            print("\n" + "="*50)
            choice = input("🔹 Select test intensity (1-4, 0 to exit): ").strip()
            
            if choice == "0":
                print("👋 Goodbye! Thank you for using Challenge 2 Test Runner")
                return 0
            elif choice in ["1", "2", "3", "4"]:
                exit_code = await run_selected_test(choice)
                
                if exit_code == 0:
                    print(f"\n✅ Test completed successfully!")
                else:
                    print(f"\n❌ Test failed with exit code: {exit_code}")
                
                # Ask if user wants to run another test
                again = input("\n🔄 Run another test? (y/N): ").strip().lower()
                if again not in ['y', 'yes']:
                    print("👋 Thank you for using Challenge 2 Test Runner!")
                    return exit_code
            else:
                print("❌ Invalid choice! Please select 1-4 or 0 to exit.")
                
        except KeyboardInterrupt:
            print("\n👋 Goodbye!")
            return 0
        except Exception as e:
            print(f"❌ Error: {e}")
            return 1

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)