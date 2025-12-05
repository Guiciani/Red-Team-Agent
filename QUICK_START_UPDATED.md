# 🚀 Quick Start Guide - Challenge 2

## 🎯 Duas Opções de Teste Disponíveis

### 🎭 **Opção 1: Mock Test** (Recomendado para início)
- ⚡ **Rápido e gratuito**
- 🚫 **Não requer Azure**
- 🎪 **Usa dados simulados**
- 🔧 **Ideal para desenvolvimento/CI**

### 🏭 **Opção 2: Production Test** (Azure Real)
- 🔥 **Recursos Azure reais**
- 💰 **Gera custos (~$500-800/mês)**
- 🎯 **Validação empresarial**
- 🚀 **Ready for production**

---

## 📋 Seletor Interativo

### Execução Recomendada
```bash
# Seletor interativo - escolha sua opção
python run_challenge2.py
```

### Execução Direta
```bash
# Mock test (rápido, gratuito, sem Azure)
python test_challenge2_mock.py

# Production test (Azure real, gera custos)
python test_challenge2.py

# Validar setup Azure
python validate_azure_production.py
```

---

## ⚙️ Configuração

### 🎭 Para Mock Test
**Nenhuma configuração necessária!**
```bash
# Execute imediatamente
python test_challenge2_mock.py
```

### 🏭 Para Production Test (Azure)
**Requer recursos Azure reais:**

1. **Configure recursos Azure**
   ```bash
   # Veja guia completo
   cat AZURE_PRODUCTION_SETUP.md
   ```

2. **Configure credenciais (.env)**
   ```bash
   cp .env.example .env
   # Edite .env com valores Azure reais
   ```

3. **Valide configuração**
   ```bash
   python validate_azure_production.py
   ```

4. **Execute teste**
   ```bash
   python test_challenge2.py
   ```

---

## 📊 Exemplos de Saída

### 🎭 Mock Test Output
```
🔴 CHALLENGE 2: WAF & SECURE FOUNDATION - MOCK TEST
============================================================
Microsoft Secure AI Framework - Mock Environment
⚠️  USING SIMULATED DATA - NO REAL AZURE RESOURCES
============================================================

🏗️ STEP 1: WAF & SECURITY COMPLIANCE (MOCK)
✅ WAF Score: 85.0% (simulated)
✅ Status: GOOD (simulated)
✅ Critical Issues: 0 (simulated)

🧪 STEP 2: QUALITY & SAFETY EVALUATIONS (MOCK)
✅ Quality Score: 96.5% (simulated)
✅ Safety Violations: 0 (simulated)

🔴 STEP 3: RED TEAM SCAN (MOCK)
✅ Total Attacks: 25 (simulated)
✅ Critical Vulnerabilities: 0 (simulated)

🏆 CHALLENGE 2 MOCK TEST RESULTS
📊 OVERALL SCORE: 100.0%
📋 RESULT: EXCELLENT - CHALLENGE 2 PASSED (Mock)
🎭 ENVIRONMENT: MOCK/SIMULATION

➡️ Ready for real Azure testing: python test_challenge2.py
```

### 🏭 Production Test Output
```
🔴 CHALLENGE 2: WAF & SECURE FOUNDATION - PRODUCTION TEST
======================================================================
Microsoft Secure AI Framework - Azure Production Environment
======================================================================

🔍 VALIDATING AZURE CONFIGURATION
✅ All required Azure configuration found

🏗️ STEP 1: WAF & SECURITY COMPLIANCE (AZURE PRODUCTION)
🔍 Connecting to Azure Resource Graph...
✅ WAF Score: 78.5% (REAL Azure Resource Graph)
✅ Security Posture: GOOD
✅ Critical Issues: 0

🧪 STEP 2: QUALITY & SAFETY EVALUATIONS (AZURE AI PRODUCTION)
🔍 Connecting to Azure AI Services...
🔍 Connecting to Azure Content Safety...
✅ Quality Score: 94.2% (REAL Azure AI evaluation)
✅ Safety Violations: 0 (REAL Azure Content Safety)

🔴 STEP 3: RED TEAM SCAN (AZURE PRODUCTION)
🚀 Running enhanced red team scan with Azure integration...
✅ Total Attacks: 47
✅ Critical Vulnerabilities: 0

🏆 CHALLENGE 2 TEST RESULTS
📊 OVERALL SCORE: 100.0%
📋 RESULT: EXCELLENT - CHALLENGE 2 PASSED
🎆 Production Ready: True

🔄 AZURE INTEGRATION STATUS:
   • Environment: PRODUCTION
   • AI Services: Azure Cognitive Services (REAL)
   • Content Safety: Azure Content Safety (REAL)
   • Challenge 2 Ready: ✅
```

---

## 🎯 Comparação Rápida

| Aspecto | Mock Test | Production Test |
|---------|-----------|-----------------|
| **Setup** | Nenhum | Azure resources necessários |
| **Tempo** | ~30 segundos | ~2-5 minutos |
| **Custos** | Gratuito | ~$500-800/mês |
| **Dados** | Simulados | Azure reais |
| **Validação** | Desenvolvimento | Enterprise |
| **CI/CD** | ✅ Ideal | ❌ Custoso |
| **Produção** | ❌ Não válido | ✅ Certificado |

---

## 🔧 Troubleshooting

### Mock Test Issues
```bash
# Se mock test falhar, verifique:
python --version  # Python 3.8+
pip list | grep asyncio  # Deps instaladas
```

### Production Test Issues  
```bash
# Se production test falhar:
python validate_azure_production.py  # Valide setup
az login  # Verifique auth
az account show  # Confirme subscription
```

---

## 📚 Próximos Passos

### Se Mock Test Passou ✅
1. **Desenvolvimento**: Continue usando mock para desenvolvimento
2. **Validação**: Configure Azure para teste de produção
3. **Deploy**: Siga `AZURE_PRODUCTION_SETUP.md`

### Se Production Test Passou ✅
1. **Produção**: Sistema validado para deploy
2. **Monitoramento**: Configure alertas Azure
3. **Manutenção**: Monitore custos e performance

---

## 🆘 Suporte

- **Mock Test**: Sem dependências externas, deve sempre funcionar
- **Production Test**: Requer Azure válido, veja troubleshooting
- **Setup Guide**: `AZURE_PRODUCTION_SETUP.md` 
- **Validation**: `python validate_azure_production.py`

---

**🎯 Recomendação: Comece com Mock Test, depois migre para Production Test quando necessário!**