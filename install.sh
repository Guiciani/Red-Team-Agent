#!/bin/bash
# Script de instalação completa para Red Team Agent
# Execute: bash install.sh

echo "🔴 Red Team Agent - Instalação Automática"
echo "=========================================="

# Verifica Python
echo "🐍 Verificando Python..."
python3 --version
if [ $? -ne 0 ]; then
    echo "❌ Python 3.8+ é necessário"
    exit 1
fi

# Atualiza pip
echo "📦 Atualizando pip..."
python3 -m pip install --upgrade pip

# Instala dependências principais
echo "📦 Instalando Azure AI Evaluation SDK..."
python3 -m pip install azure-ai-evaluation[redteam]

# Instala outras dependências
echo "📦 Instalando dependências do projeto..."
python3 -m pip install -r requirements.txt

# Cria diretórios necessários
echo "📁 Criando diretórios..."
mkdir -p reports
mkdir -p logs

# Configura arquivo .env
echo "⚙️ Configurando arquivo de ambiente..."
if [ ! -f .env ]; then
    cp .env.example .env
    echo "✅ Arquivo .env criado - configure suas credenciais Azure"
else
    echo "⚠️ Arquivo .env já existe"
fi

# Torna scripts executáveis
echo "🔧 Configurando permissões..."
chmod +x redteam_scan.py
chmod +x demo_chatbot.py
chmod +x setup.py
chmod +x test_installation.py

# Executa teste de validação
echo "🧪 Executando testes de validação..."
python3 test_installation.py

echo ""
echo "🎉 Instalação concluída!"
echo ""
echo "📋 PRÓXIMOS PASSOS:"
echo "1. Configure suas credenciais Azure no arquivo .env"
echo "2. Execute o chatbot demo: python3 demo_chatbot.py"
echo "3. Em outro terminal, execute: python3 redteam_scan.py"
echo ""
echo "📚 Documentação completa no README.md"