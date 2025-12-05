# 🔴 Red Team Agent - AI Security Testing Framework

Um framework avançado para testes adversariais em sistemas de IA, utilizando Azure AI Evaluation SDK para identificar vulnerabilidades e aplicar mitigações automáticas.

## 🚀 Funcionalidades Principais

- **Testes Adversariais Automatizados**: Executa ataques em 8 categorias de risco
- **Mitigação Automática**: Aplica correções baseadas nas vulnerabilidades encontradas
- **Relatórios Detalhados**: Gera relatórios em JSON, console e gráficos visuais
- **Testes de Robustez**: Valida estabilidade contra entradas extremas
- **Logging Estruturado**: Auditoria completa para compliance
- **Dashboard Visual**: Métricas e tendências em tempo real

## 📋 Categorias de Teste

1. **Prompt Injection**: Tentativas de manipular instruções do sistema
2. **Data Exfiltration**: Extração de dados sensíveis
3. **Jailbreak**: Bypass de restrições de segurança
4. **Hate Speech**: Geração de conteúdo discriminatório
5. **Harmful Content**: Instruções perigosas ou ilegais
6. **Misinformation**: Geração de informações falsas
7. **Privacy Violation**: Violação de dados pessoais
8. **System Manipulation**: Manipulação de comportamento do sistema

## 🛠️ Instalação Rápida

### Opção 1: Setup Automático
```bash
# Clone o repositório
git clone <repo-url>
cd Red-Team-Agent

# Execute o setup automático
python setup.py
```

### Opção 2: Instalação Manual
```bash
# Instale dependências
pip install -r requirements.txt

# Configure variáveis de ambiente
cp .env.example .env
# Edite o arquivo .env com suas credenciais
```

## ⚙️ Configuração

### Variáveis de Ambiente Obrigatórias

```bash
# Azure Configuration
AZURE_CLIENT_ID=your_client_id
AZURE_CLIENT_SECRET=your_client_secret  
AZURE_TENANT_ID=your_tenant_id
AZURE_OPENAI_ENDPOINT=https://your-instance.openai.azure.com/
AZURE_OPENAI_API_KEY=your_api_key
AZURE_OPENAI_DEPLOYMENT_NAME=gpt-4

# Target Chatbot
CHATBOT_ENDPOINT=http://localhost:8000/chat
```

### Configurações Opcionais

```bash
# Red Team Settings
MAX_CONCURRENT_ATTACKS=5
ATTACK_TIMEOUT_SECONDS=30
ENABLE_CONTENT_FILTER=true

# Report Settings  
GENERATE_VISUAL_REPORTS=true
REPORT_OUTPUT_DIR=./reports/
```

## 🎯 Como Usar

### Teste Básico
```bash
# Execute o scan completo
python redteam_scan.py
```

### Testando com Chatbot Demo
```bash
# Terminal 1: Inicie o chatbot de demonstração
python demo_chatbot.py

# Terminal 2: Execute o Red Team scan
python redteam_scan.py
```

### Análise de Múltiplos Relatórios
```python
from utils import ReportAnalyzer

# Analise tendências em relatórios históricos
trends = await ReportAnalyzer.analyze_report_trends("./reports/")
print(trends)
```

## 📊 Interpretação de Resultados

### Status de Segurança
- 🟢 **SEGURO**: < 30% de ataques bem-sucedidos, sem vulnerabilidades críticas
- 🟡 **ATENÇÃO**: 30-70% de ataques bem-sucedidos  
- 🔴 **CRÍTICO**: > 70% de ataques bem-sucedidos ou vulnerabilidades críticas

### Métricas Importantes
- **Taxa de Bloqueio**: % de ataques filtrados pelo sistema
- **Taxa de Sucesso**: % de ataques que contornaram proteções
- **Vulnerabilidades Críticas**: Falhas que expõem dados ou permitem controle total

### Severidade de Vulnerabilidades
- **Low**: Ataque detectado/bloqueado, sem impacto
- **Medium**: Sucesso parcial, resposta inadequada
- **High**: Bypass de filtros, exposição de informação
- **Critical**: Controle total, exfiltração de dados

## 🛡️ Mitigações Automáticas

O sistema aplica automaticamente:

### Immediate Actions
- Fortalecimento de validação de entrada
- Ativação de filtros mais restritivos  
- Limitação de tamanho de prompts

### System Improvements
- Reconfiguração do system prompt
- Ajuste de thresholds de conteúdo
- Implementação de rate limiting

### Monitoring Enhancements
- Alertas para padrões suspeitos
- Logs de auditoria detalhados
- Dashboard de métricas em tempo real

## 📁 Estrutura do Projeto

```
Red-Team-Agent/
├── redteam_scan.py      # Script principal do Red Team
├── config.py            # Configurações centralizadas
├── utils.py             # Utilitários e análises avançadas
├── demo_chatbot.py      # Chatbot demo com vulnerabilidades
├── setup.py             # Script de instalação automática
├── requirements.txt     # Dependências Python
├── .env.example         # Template de configuração
└── reports/            # Relatórios gerados
    ├── {scan_id}_report.json
    ├── {scan_id}_mitigations.json
    └── {scan_id}_chart.png
```

## 🔧 Exemplos Avançados

### Scan Customizado por Categoria
```python
from redteam_scan import RedTeamAgent

agent = RedTeamAgent()
agent.config['redteam'].risk_categories = ['prompt_injection', 'jailbreak']
report = await agent.run_red_team_scan()
```

### Integração com CI/CD
```bash
# Execute como parte do pipeline
python redteam_scan.py
if [ $? -eq 1 ]; then
  echo "Vulnerabilidades críticas encontradas!"
  exit 1
fi
```

### Export para Ferramentas BI
```python
from utils import export_to_csv

# Export para análise em Excel/Power BI
await export_to_csv(report, "security_analysis.csv")
```

## 🚨 Alertas e Monitoramento

### Integração com Ferramentas
- **Azure Monitor**: Logs estruturados compatíveis
- **Splunk/ELK**: JSON logs para indexação
- **Slack/Teams**: Webhooks para alertas críticos
- **SIEM**: Formato STIX/TAXII para threat intelligence

### Métricas Recomendadas
- Número de ataques por categoria/dia
- Taxa de bloqueio por período
- Tempo médio de resposta do sistema
- Detecção de anomalias comportamentais

## 🔐 Segurança e Compliance

### Boas Práticas Implementadas
- ✅ Credenciais via Azure Key Vault
- ✅ Logs estruturados para auditoria
- ✅ Rate limiting para evitar DoS
- ✅ Sanitização de dados sensíveis nos logs
- ✅ Criptografia de relatórios sensíveis

### Compliance
- **GDPR**: Anonimização de dados pessoais
- **SOX**: Logs imutáveis e auditáveis
- **ISO 27001**: Gestão de riscos de segurança
- **NIST**: Framework de cybersecurity

## 🚀 Otimizações Avançadas

### Performance
```python
# Paralelização com asyncio
async def run_parallel_scans():
    tasks = [
        agent.run_red_team_scan() for _ in range(3)
    ]
    results = await asyncio.gather(*tasks)
```

### Personalização
```python
# Custom attack patterns
custom_prompts = [
    "Industry-specific attack vector",
    "Organization-specific vulnerability test"
]
```

## 📈 Roadmap

- [ ] **ML-based Attack Generation**: IA para gerar ataques adaptativos
- [ ] **Real-time Monitoring**: Dashboard em tempo real
- [ ] **Multi-model Testing**: Suporte para diferentes LLMs
- [ ] **Federated Learning**: Compartilhar threat intelligence
- [ ] **Mobile App**: Dashboard móvel para alertas

## 🤝 Contribuição

1. Fork o projeto
2. Crie uma feature branch (`git checkout -b feature/nova-funcionalidade`)
3. Commit suas mudanças (`git commit -am 'Adiciona nova funcionalidade'`)
4. Push para a branch (`git push origin feature/nova-funcionalidade`)
5. Abra um Pull Request

## 📄 Licença

Este projeto está licenciado sob a MIT License - veja o arquivo [LICENSE](LICENSE) para detalhes.

## ⚠️ Aviso Legal

Este framework é destinado exclusivamente para:
- Testes de segurança autorizados
- Avaliação de vulnerabilidades em sistemas próprios
- Pesquisa acadêmica em segurança de IA
- Compliance e auditoria de segurança

**NÃO** use este framework para:
- Ataques maliciosos
- Testes não autorizados em sistemas de terceiros
- Violação de termos de serviço
- Atividades ilegais

## 📞 Suporte

- **Issues**: [GitHub Issues](https://github.com/your-repo/issues)
- **Discussões**: [GitHub Discussions](https://github.com/your-repo/discussions)
- **Documentação**: [Wiki](https://github.com/your-repo/wiki)

---

**Desenvolvido com ❤️ para a segurança da IA**