#!/usr/bin/env python3
"""
Script de instalação e configuração automática do Red Team Agent
Facilita a configuração inicial do ambiente
"""

import os
import sys
import subprocess
from pathlib import Path

def run_command(cmd: str, description: str = None):
    """Executa comando do sistema com tratamento de erro"""
    if description:
        print(f"🔧 {description}...")
    
    try:
        result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
        if result.stdout:
            print(result.stdout)
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Erro: {e}")
        if e.stderr:
            print(f"Stderr: {e.stderr}")
        return False

def main():
    print("🔴 Red Team Agent - Setup Automático")
    print("=" * 50)
    
    # 1. Verificar Python
    if sys.version_info < (3, 8):
        print("❌ Python 3.8+ é necessário")
        sys.exit(1)
    
    print(f"✅ Python {sys.version}")
    
    # 2. Instalar dependências
    if not run_command("pip install -r requirements.txt", "Instalando dependências"):
        print("⚠️ Algumas dependências podem ter falhado")
    
    # 3. Criar diretório de relatórios
    reports_dir = Path("./reports")
    reports_dir.mkdir(exist_ok=True)
    print(f"✅ Diretório de relatórios criado: {reports_dir}")
    
    # 4. Configurar arquivo .env
    env_file = Path(".env")
    if not env_file.exists():
        import shutil
        shutil.copy(".env.example", ".env")
        print("📝 Arquivo .env criado a partir do exemplo")
        print("⚠️ IMPORTANTE: Edite o arquivo .env com suas credenciais Azure")
    else:
        print("✅ Arquivo .env já existe")
    
    # 5. Verificar Azure CLI (opcional)
    if run_command("az --version", "Verificando Azure CLI"):
        print("✅ Azure CLI disponível")
    else:
        print("⚠️ Azure CLI não encontrado (opcional para autenticação)")
    
    # 6. Teste rápido de importação
    try:
        import azure.ai.evaluation
        print("✅ Azure AI Evaluation SDK importado com sucesso")
    except ImportError:
        print("❌ Erro ao importar Azure AI Evaluation SDK")
        print("💡 Tente: pip install azure-ai-evaluation[redteam] --upgrade")
        return False
    
    print("\\n🎉 Setup concluído!")
    print("\\nPróximos passos:")
    print("1. Configure suas credenciais no arquivo .env")
    print("2. Execute: python redteam_scan.py")
    print("3. Verifique os relatórios em ./reports/")
    
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)