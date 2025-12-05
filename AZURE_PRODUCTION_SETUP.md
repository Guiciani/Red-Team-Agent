# Azure Production Setup Guide - Challenge 2

Este guia detalha como configurar recursos Azure reais para executar o Challenge 2 em produção.

## 🎯 Recursos Azure Necessários

### 1. Azure AI Services
```bash
# Criar Azure AI Services (multi-service)
az cognitiveservices account create \
    --name "redteam-ai-services" \
    --resource-group "rg-redteam-challenge2" \
    --kind "AIServices" \
    --sku "S0" \
    --location "eastus" \
    --custom-domain "redteam-ai-services"

# Obter chave e endpoint
az cognitiveservices account keys list \
    --name "redteam-ai-services" \
    --resource-group "rg-redteam-challenge2"

az cognitiveservices account show \
    --name "redteam-ai-services" \
    --resource-group "rg-redteam-challenge2" \
    --query "properties.endpoint"
```

### 2. Azure AI Content Safety
```bash
# Criar Azure AI Content Safety
az cognitiveservices account create \
    --name "redteam-content-safety" \
    --resource-group "rg-redteam-challenge2" \
    --kind "ContentSafety" \
    --sku "S0" \
    --location "eastus"

# Obter chave e endpoint
az cognitiveservices account keys list \
    --name "redteam-content-safety" \
    --resource-group "rg-redteam-challenge2"

az cognitiveservices account show \
    --name "redteam-content-safety" \
    --resource-group "rg-redteam-challenge2" \
    --query "properties.endpoint"
```

### 3. Service Principal para Automação
```bash
# Criar Service Principal
az ad sp create-for-rbac \
    --name "sp-redteam-challenge2" \
    --role "Contributor" \
    --scopes "/subscriptions/{subscription-id}/resourceGroups/rg-redteam-challenge2"

# Adicionar permissão para Resource Graph
az role assignment create \
    --assignee "{service-principal-id}" \
    --role "Reader" \
    --scope "/subscriptions/{subscription-id}"
```

### 4. Azure OpenAI (Opcional)
```bash
# Criar Azure OpenAI (se disponível na região)
az cognitiveservices account create \
    --name "redteam-openai" \
    --resource-group "rg-redteam-challenge2" \
    --kind "OpenAI" \
    --sku "S0" \
    --location "eastus"

# Fazer deploy de modelo
az cognitiveservices account deployment create \
    --name "redteam-openai" \
    --resource-group "rg-redteam-challenge2" \
    --deployment-name "gpt-4" \
    --model-name "gpt-4" \
    --model-version "0613" \
    --model-format "OpenAI" \
    --scale-settings-scale-type "Standard"
```

## 🔐 Configuração de Credenciais (.env)

Crie/atualize seu arquivo `.env` com os valores reais:

```env
# ===== AZURE CREDENTIALS =====
AZURE_CLIENT_ID="00000000-0000-0000-0000-000000000000"
AZURE_CLIENT_SECRET="your-service-principal-secret"
AZURE_TENANT_ID="00000000-0000-0000-0000-000000000000"
AZURE_SUBSCRIPTION_ID="00000000-0000-0000-0000-000000000000"

# ===== AZURE AI SERVICES =====
AZURE_AI_SERVICES_KEY="your-ai-services-key-here"
AZURE_AI_SERVICES_ENDPOINT="https://redteam-ai-services.cognitiveservices.azure.com/"

# ===== AZURE AI CONTENT SAFETY =====
AZURE_CONTENT_SAFETY_KEY="your-content-safety-key-here"
AZURE_CONTENT_SAFETY_ENDPOINT="https://redteam-content-safety.cognitiveservices.azure.com/"

# ===== AZURE OPENAI (OPCIONAL) =====
AZURE_OPENAI_KEY="your-openai-key-here"
AZURE_OPENAI_ENDPOINT="https://redteam-openai.openai.azure.com/"
AZURE_OPENAI_DEPLOYMENT="gpt-4"
AZURE_OPENAI_API_VERSION="2024-02-01"

# ===== TARGET APPLICATION =====
CHATBOT_BASE_URL="https://your-target-app.azurewebsites.net"
CHATBOT_HEALTH_ENDPOINT="/health"

# ===== CONFIGURATION =====
RED_TEAM_MAX_CONCURRENT=10
RED_TEAM_REQUEST_DELAY=0.5
RED_TEAM_TIMEOUT=60
LOG_LEVEL="INFO"
```

## 🚀 Execução em Produção

### 1. Teste de Conectividade
```bash
# Verificar credenciais Azure
az account show

# Testar acesso aos recursos
az cognitiveservices account show \
    --name "redteam-ai-services" \
    --resource-group "rg-redteam-challenge2"
```

### 2. Executar Challenge 2 Produção
```bash
# Executar teste completo com recursos Azure reais
python test_challenge2.py
```

### 3. Output Esperado (Produção)
```
🔴 CHALLENGE 2: WAF & SECURE FOUNDATION - PRODUCTION TEST
======================================================================
Microsoft Secure AI Framework - Azure Production Environment
======================================================================

🔍 VALIDATING AZURE CONFIGURATION
--------------------------------------------------
✅ All required Azure configuration found

🏗️ STEP 1: WAF & SECURITY COMPLIANCE (AZURE PRODUCTION)
------------------------------------------------------------
🔍 Connecting to Azure Resource Graph...
🔍 Running WAF compliance checks...
📄 Generating WAF compliance report...
✅ WAF Score: 78.5%
✅ Security Posture: GOOD
✅ Critical Issues: 0

🧪 STEP 2: QUALITY & SAFETY EVALUATIONS (AZURE AI PRODUCTION)
------------------------------------------------------------
🔍 Connecting to Azure AI Services...
📋 Running quality evaluation against ground truth...
🔍 Connecting to Azure Content Safety...
🛡️ Running content safety analysis...
✅ Quality Score: 94.2%
✅ Safety Violations: 0
✅ Content Filter Activations: 15

🔴 STEP 3: RED TEAM SCAN (AZURE PRODUCTION)
------------------------------------------------------------
🔍 Initializing Enhanced Red Team Agent...
🚀 Running enhanced red team scan with Azure integration...
✅ Total Attacks: 47
✅ Successful Attacks: 5
✅ Critical Vulnerabilities: 0
✅ WAF Compliance Score: 85.2%

🔧 STEP 4: AUTOMATED MITIGATIONS (AZURE PRODUCTION)
------------------------------------------------------------
🔍 Analyzing vulnerabilities for mitigation...
📄 Found 2 vulnerabilities to address
⚙️ Applying 2 automated fixes...
✅ Total Vulnerabilities Found: 2
✅ Mitigations Applied: 2
✅ Automated Fixes: 2
✅ Manual Actions Required: 0

============================================================
🏆 CHALLENGE 2 TEST RESULTS
============================================================

📊 OVERALL SCORE: 100.0%
📋 RESULT: EXCELLENT - CHALLENGE 2 PASSED

🎯 SUCCESS CRITERIA:
   • Waf Compliant: ✅
   • Quality Met: ✅
   • Safety Met: ✅
   • No Critical Vulns: ✅
   • Mitigations Applied: ✅

🔄 AZURE INTEGRATION STATUS:
   • WAF Framework: Azure Resource Graph + Well-Architected Framework
   • AI Safety: Azure AI Content Safety Production
   • Evaluation: Azure AI Foundry Production
   • Red Teaming: Enhanced Red Team Agent + PyRIT
   • Environment: PRODUCTION
   • Challenge 2 Ready: ✅

🏁 Challenge 2 Production Test Completed
📈 Overall Score: 100.0%
🎆 Production Ready: True
✅ Challenge 2: PASSED
```

## 🔧 Troubleshooting

### Erro: Authentication Failed
```bash
# Verificar login
az login

# Verificar service principal
az ad sp show --id "{client-id}"

# Testar credenciais
az account get-access-token
```

### Erro: Resource Not Found
```bash
# Verificar recursos existem
az cognitiveservices account list \
    --resource-group "rg-redteam-challenge2"

# Verificar permissões
az role assignment list --assignee "{client-id}"
```

### Erro: Rate Limiting
```
# Ajustar configuração no .env
RED_TEAM_REQUEST_DELAY=2.0
RED_TEAM_MAX_CONCURRENT=5
```

### Erro: Content Safety Blocked
```
# Verificar configuração de filtros
# Logs mostrarão detalhes dos bloqueios
# Ajustar prompts se necessário
```

## 📊 Monitoramento em Produção

### 1. Application Insights
```bash
# Criar Application Insights
az monitor app-insights component create \
    --app "redteam-insights" \
    --location "eastus" \
    --resource-group "rg-redteam-challenge2"

# Adicionar ao .env
APPLICATIONINSIGHTS_CONNECTION_STRING="InstrumentationKey=..."
```

### 2. Metrics Dashboard
- WAF Compliance Score trends
- Red Team attack success rates
- Content Safety filter activations
- Quality evaluation scores

### 3. Alertas Automáticos
- Critical vulnerabilities found
- WAF compliance below threshold
- Safety violations detected
- Quality score degradation

## 🏆 Validação de Produção

Para confirmar que está usando recursos Azure reais:

1. **Verifique os logs**: Devem mostrar endpoints Azure reais
2. **Check Azure portal**: Veja metrics nos recursos
3. **Examine costs**: Resources em uso geram custos
4. **Validate responses**: Respostas reais vs mock são diferentes

## 💰 Custos Estimados (USD/mês)

- **Azure AI Services (S0)**: ~$242/mês
- **Azure AI Content Safety (S0)**: ~$242/mês  
- **Azure OpenAI (opcional)**: Baseado em tokens consumidos
- **Resource Graph queries**: Primeiras 1000 queries gratuitas

**Total Estimado**: ~$500-800/mês para uso intensivo

## 🔄 Próximos Passos

1. **Deploy recursos Azure** usando os comandos acima
2. **Configure credenciais** no arquivo .env
3. **Execute teste produção**: `python test_challenge2.py`
4. **Valide resultados** nos Azure resources
5. **Configure monitoramento** para uso contínuo

---

**🎯 Este setup garante que o Challenge 2 rode com recursos Azure reais em produção, atendendo todos os Success Criteria Microsoft com dados e métricas reais.**