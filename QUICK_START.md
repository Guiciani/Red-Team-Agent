# 🔴 Red Team Agent - Instalação e Uso Rápido

## 🚀 Instalação em 3 Passos

```bash
# 1. Instale as dependências
pip install azure-ai-evaluation[redteam] fastapi uvicorn aiohttp python-dotenv structlog tabulate pandas

# 2. Configure as credenciais (edite o .env)
cp .env.example .env

# 3. Execute o teste
python redteam_scan.py
```

## 🎯 Uso Básico

### Opção 1: Com Chatbot Demo
```bash
# Terminal 1: Chatbot alvo
python demo_chatbot.py

# Terminal 2: Red Team scan  
python redteam_scan.py
```

### Opção 2: Contra endpoint externo
```bash
# Configure CHATBOT_ENDPOINT no .env
# Execute:
python redteam_scan.py
```

## 📊 Estrutura dos Arquivos

- `redteam_scan.py` - Script principal do Red Team Agent
- `config.py` - Configurações centralizadas
- `demo_chatbot.py` - Chatbot vulnerável para testes
- `utils.py` - Utilitários de análise e relatórios
- `example_usage.py` - Exemplos de uso programático
- `test_installation.py` - Validação da instalação
- `setup.py` / `install.sh` - Scripts de instalação

## ⚙️ Configuração Mínima (.env)

```bash
AZURE_CLIENT_ID=your_client_id
AZURE_CLIENT_SECRET=your_client_secret
AZURE_TENANT_ID=your_tenant_id
AZURE_OPENAI_ENDPOINT=https://your-instance.openai.azure.com/
AZURE_OPENAI_API_KEY=your_api_key
CHATBOT_ENDPOINT=http://localhost:8000/chat
```

## 📈 Resultados Esperados

### Console Output:
```
🔴 RED TEAM AGENT - RELATÓRIO DE SEGURANÇA
==========================================
📊 RESUMO EXECUTIVO:
   • Scan ID: redteam_scan_1735123456
   • Total de ataques: 45
   • Ataques bloqueados: 32 (71.1%)
   • Ataques bem-sucedidos: 8 (17.8%)
   • Vulnerabilidades críticas: 2

🚨 STATUS DE SEGURANÇA: 🔴 CRÍTICO
💡 RECOMENDAÇÕES:
   1. ⚠️ URGENTE: Vulnerabilidades críticas - revisar
   2. 🛡️ Implementar validação rigorosa de entrada
```

### Arquivos Gerados:
- `reports/{scan_id}_report.json` - Relatório detalhado
- `reports/{scan_id}_mitigations.json` - Ações de mitigação
- `reports/{scan_id}_chart.png` - Gráficos (opcional)

## 🎛️ Personalização

### Categorias Específicas:
```python
from redteam_scan import RedTeamAgent

agent = RedTeamAgent()
agent.config['redteam'].risk_categories = ['prompt_injection', 'jailbreak']
report = await agent.run_red_team_scan()
```

### Configuração via Código:
```python
import os
os.environ['MAX_CONCURRENT_ATTACKS'] = '10'
os.environ['ATTACK_TIMEOUT_SECONDS'] = '60'
```

## 🚨 Troubleshooting

### Erro: Módulos não encontrados
```bash
pip install -r requirements.txt
```

### Erro: Credenciais Azure
- Configure todas as variáveis AZURE_* no .env
- Use `az login` para autenticação

### Erro: Timeout de conexão  
- Verifique se o CHATBOT_ENDPOINT está acessível
- Aumente ATTACK_TIMEOUT_SECONDS

## 📞 Suporte

- Execute `python test_installation.py` para diagnóstico
- Veja logs detalhados em `./logs/`
- Consulte README.md para documentação completa