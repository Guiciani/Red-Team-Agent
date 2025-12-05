#!/usr/bin/env python3
"""
Azure Production Validation Script
=================================

Script para validar se a configuração Azure está correta para produção
"""

import os
import sys
import asyncio
from azure.identity import DefaultAzureCredential, ClientSecretCredential
from azure.core.exceptions import AzureError

async def validate_azure_credentials():
    """Valida credenciais Azure"""
    print("🔐 VALIDATING AZURE CREDENTIALS")
    print("-" * 50)
    
    try:
        # Testa Service Principal se configurado
        if all([os.getenv('AZURE_CLIENT_ID'), 
               os.getenv('AZURE_CLIENT_SECRET'), 
               os.getenv('AZURE_TENANT_ID')]):
            credential = ClientSecretCredential(
                tenant_id=os.getenv('AZURE_TENANT_ID'),
                client_id=os.getenv('AZURE_CLIENT_ID'),
                client_secret=os.getenv('AZURE_CLIENT_SECRET')
            )
            print("✅ Service Principal configured")
        else:
            credential = DefaultAzureCredential()
            print("✅ Using Default Azure Credential")
        
        # Testa obtenção de token
        token = credential.get_token("https://management.azure.com/.default")
        print("✅ Successfully obtained access token")
        return True
        
    except Exception as e:
        print(f"❌ Credential validation failed: {e}")
        return False

async def validate_azure_ai_services():
    """Valida Azure AI Services"""
    print("\n🧠 VALIDATING AZURE AI SERVICES")
    print("-" * 50)
    
    required_vars = [
        'AZURE_AI_SERVICES_KEY',
        'AZURE_AI_SERVICES_ENDPOINT'
    ]
    
    for var in required_vars:
        if os.getenv(var):
            print(f"✅ {var}: Configured")
        else:
            print(f"❌ {var}: Missing")
            return False
    
    # Testa conectividade
    try:
        import requests
        endpoint = os.getenv('AZURE_AI_SERVICES_ENDPOINT')
        headers = {
            'Ocp-Apim-Subscription-Key': os.getenv('AZURE_AI_SERVICES_KEY')
        }
        
        # Teste simples de conectividade
        response = requests.get(f"{endpoint.rstrip('/')}/", headers=headers, timeout=10)
        print(f"✅ AI Services endpoint reachable: {response.status_code}")
        return True
        
    except Exception as e:
        print(f"❌ AI Services connectivity test failed: {e}")
        return False

async def validate_content_safety():
    """Valida Azure Content Safety"""
    print("\n🛡️ VALIDATING AZURE CONTENT SAFETY")
    print("-" * 50)
    
    required_vars = [
        'AZURE_CONTENT_SAFETY_KEY',
        'AZURE_CONTENT_SAFETY_ENDPOINT'
    ]
    
    for var in required_vars:
        if os.getenv(var):
            print(f"✅ {var}: Configured")
        else:
            print(f"❌ {var}: Missing")
            return False
    
    # Testa Content Safety API
    try:
        from azure.ai.contentsafety import ContentSafetyClient
        from azure.identity import AzureKeyCredential
        
        endpoint = os.getenv('AZURE_CONTENT_SAFETY_ENDPOINT')
        key = os.getenv('AZURE_CONTENT_SAFETY_KEY')
        
        client = ContentSafetyClient(endpoint, AzureKeyCredential(key))
        print("✅ Content Safety client initialized successfully")
        return True
        
    except Exception as e:
        print(f"❌ Content Safety validation failed: {e}")
        return False

async def validate_subscription_access():
    """Validates subscription access for Resource Graph"""
    print("\n📊 VALIDATING SUBSCRIPTION ACCESS")
    print("-" * 50)
    
    subscription_id = os.getenv('AZURE_SUBSCRIPTION_ID')
    if not subscription_id:
        print("❌ AZURE_SUBSCRIPTION_ID not configured")
        return False
    
    print(f"✅ Subscription ID: {subscription_id}")
    
    try:
        # Testa acesso ao Resource Graph
        from azure.mgmt.resourcegraph import ResourceGraphClient
        from azure.identity import DefaultAzureCredential
        
        credential = DefaultAzureCredential()
        client = ResourceGraphClient(credential)
        print("✅ Resource Graph client initialized")
        return True
        
    except Exception as e:
        print(f"❌ Resource Graph validation failed: {e}")
        return False

def validate_environment_completeness():
    """Validates if all necessary variables are configured"""
    print("\n🔍 ENVIRONMENT COMPLETENESS CHECK")
    print("-" * 50)
    
    required_vars = [
        # Azure Core
        'AZURE_SUBSCRIPTION_ID',
        'AZURE_TENANT_ID',
        
        # AI Services
        'AZURE_AI_SERVICES_KEY',
        'AZURE_AI_SERVICES_ENDPOINT',
        
        # Content Safety
        'AZURE_CONTENT_SAFETY_KEY',
        'AZURE_CONTENT_SAFETY_ENDPOINT',
        
        # Target App (opcional mas recomendado)
        'CHATBOT_BASE_URL'
    ]
    
    optional_vars = [
        'AZURE_CLIENT_ID',
        'AZURE_CLIENT_SECRET',
        'AZURE_OPENAI_KEY',
        'AZURE_OPENAI_ENDPOINT'
    ]
    
    missing_required = []
    for var in required_vars:
        if os.getenv(var):
            print(f"✅ {var}")
        else:
            print(f"❌ {var}")
            missing_required.append(var)
    
    print(f"\nOptional variables:")
    for var in optional_vars:
        if os.getenv(var):
            print(f"✅ {var} (optional)")
        else:
            print(f"⚪ {var} (optional - not configured)")
    
    return len(missing_required) == 0

def print_production_readiness_summary(results):
    """Imprime resumo de prontidão para produção"""
    print("\n" + "="*60)
    print("🏆 AZURE PRODUCTION READINESS SUMMARY")
    print("="*60)
    
    total_checks = len(results)
    passed_checks = sum(1 for r in results.values() if r)
    score = (passed_checks / total_checks) * 100
    
    print(f"\n📊 Overall Score: {score:.1f}%")
    print(f"✅ Passed: {passed_checks}/{total_checks}")
    
    print(f"\n🎯 Check Results:")
    for check_name, result in results.items():
        icon = "✅" if result else "❌"
        print(f"   {icon} {check_name}")
    
    if score >= 90:
        status = "🎉 READY FOR PRODUCTION"
        recommendation = "All systems go! You can run Challenge 2 with Azure production resources."
    elif score >= 70:
        status = "⚠️ MOSTLY READY"
        recommendation = "Minor issues found. Address them for optimal production experience."
    elif score >= 50:
        status = "🔧 NEEDS CONFIGURATION"
        recommendation = "Several configuration issues found. Fix them before production use."
    else:
        status = "❌ NOT READY"
        recommendation = "Major configuration problems. Complete Azure setup before proceeding."
    
    print(f"\n🚀 Production Status: {status}")
    print(f"💡 Recommendation: {recommendation}")
    
    if score < 100:
        print(f"\n📝 Next Steps:")
        if not results.get('Environment Complete', True):
            print("   1. Complete .env file configuration")
        if not results.get('Azure Credentials', True):
            print("   2. Configure Azure authentication (az login or service principal)")
        if not results.get('AI Services', True):
            print("   3. Deploy Azure AI Services and configure keys")
        if not results.get('Content Safety', True):
            print("   4. Deploy Azure Content Safety and configure keys")
        if not results.get('Subscription Access', True):
            print("   5. Verify subscription permissions for Resource Graph")
        
        print(f"\n📖 See AZURE_PRODUCTION_SETUP.md for detailed instructions")
    
    print("\n" + "="*60)

async def main():
    """Função principal de validação"""
    print("🔍 AZURE PRODUCTION ENVIRONMENT VALIDATION")
    print("="*60)
    print("This script validates your Azure configuration for Challenge 2 production use")
    print("="*60)
    
    # Carrega .env se existir
    try:
        from dotenv import load_dotenv
        load_dotenv()
        print("✅ Loaded .env file")
    except:
        print("⚪ No .env file found (using environment variables)")
    
    # Executa todas as validações
    results = {}
    
    results['Environment Complete'] = validate_environment_completeness()
    results['Azure Credentials'] = await validate_azure_credentials()
    results['AI Services'] = await validate_azure_ai_services()
    results['Content Safety'] = await validate_content_safety()
    results['Subscription Access'] = await validate_subscription_access()
    
    # Imprime resumo final
    print_production_readiness_summary(results)
    
    # Exit code baseado no resultado
    passed_checks = sum(1 for r in results.values() if r)
    total_checks = len(results)
    
    if passed_checks == total_checks:
        print("\n🎯 Ready to run: python test_challenge2.py")
        return 0
    elif passed_checks >= total_checks * 0.7:
        print("\n⚠️ You may proceed with caution: python test_challenge2.py")
        return 0
    else:
        print("\n❌ Please complete configuration before running Challenge 2")
        return 1

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)