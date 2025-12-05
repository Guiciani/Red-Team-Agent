# Challenge 2: WAF & Secure Foundation - English Version

## 🏆 **Three-Tier Testing System**

Complete implementation of Microsoft Challenge 2 with **three intensity levels** for different business needs and budgets.

---

## 🎯 **Available Test Intensities**

### **1️⃣ Low Intensity (20%)**
- **File**: `test_challenge2_low_intensity.py`
- **Cost**: ~$50-100/month
- **Time**: 2-4 minutes
- **Use Cases**: Demos, POCs, quick validation, cost-sensitive testing
- **Coverage**: 50 attacks, 5 WAF checks, light evaluations

### **2️⃣ Moderate Intensity (50%)**  
- **File**: `test_challenge2_moderate_intensity.py`
- **Cost**: ~$200-400/month
- **Time**: 5-10 minutes
- **Use Cases**: Regular validation, integration testing, balanced cost-coverage
- **Coverage**: 125 attacks, 11 WAF checks, moderate evaluations

### **3️⃣ Full Intensity (100%)**
- **File**: `test_challenge2_full_intensity.py` 
- **Cost**: ~$500-800/month
- **Time**: 10-25 minutes
- **Use Cases**: Certification, production-ready validation, comprehensive testing
- **Coverage**: 250+ attacks, 20+ WAF checks, full evaluations

### **4️⃣ Mock Testing (Development)**
- **File**: `test_challenge2_mock.py`
- **Cost**: $0/month (no Azure calls)
- **Time**: 1-2 minutes
- **Use Cases**: Development, CI/CD, testing without Azure costs
- **Coverage**: Simulated responses, full test flow validation

---

## 🚀 **Quick Start Commands**

### **Interactive Test Selector** (Recommended)
```bash
python run_challenge2_tests.py
```

### **Direct Test Execution**

#### **Low Intensity (Fast & Cheap)**
```bash
python test_challenge2_low_intensity.py
```

#### **Moderate Intensity (Balanced)**
```bash
python test_challenge2_moderate_intensity.py
```

#### **Full Intensity (Comprehensive)**
```bash
python test_challenge2_full_intensity.py
```

#### **Mock Testing (Zero Cost)** ⭐
```bash
python test_challenge2_mock.py
```

---

## 🧪 **Mock Testing Command**

For **development and testing without Azure costs**:

```bash
# Zero-cost development testing
python test_challenge2_mock.py

# Or use the interactive selector and choose option 4
python run_challenge2_tests.py
# Then select: 4 (Mock Testing)
```

**Mock Testing Features:**
- ✅ **Zero Azure costs** - no API calls
- ✅ **Fast execution** - 1-2 minutes
- ✅ **Full test coverage** - validates entire flow
- ✅ **CI/CD friendly** - perfect for automated testing
- ✅ **Development ready** - test changes without Azure setup

---

## 📋 **Prerequisites**

### **For Production Testing (Options 1-3)**
```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Configure Azure authentication
az login

# 3. Set environment variables (.env file)
AZURE_SUBSCRIPTION_ID=your-subscription-id
AZURE_AI_SERVICES_ENDPOINT=your-endpoint
AZURE_AI_SERVICES_KEY=your-key
AZURE_CONTENT_SAFETY_ENDPOINT=your-content-safety-endpoint
AZURE_CONTENT_SAFETY_KEY=your-content-safety-key
```

### **For Mock Testing (Option 4)**
```bash
# Only dependencies needed - no Azure setup required
pip install -r requirements.txt
```

---

## 🎯 **Usage Recommendations**

| Scenario | Recommended Test | Reason |
|----------|------------------|---------|
| **Demo/POC** | Low Intensity | Fast, cheap, good coverage |
| **Regular Validation** | Moderate Intensity | Balanced cost-coverage |
| **Production Certification** | Full Intensity | Comprehensive validation |
| **Development/CI/CD** | Mock Testing | Zero cost, fast feedback |
| **Budget Constrained** | Low Intensity → Mock | Start cheap, upgrade as needed |
| **Security Audit** | Full Intensity | Complete compliance validation |

---

## 📊 **Test Comparison**

| Feature | Low | Moderate | Full | Mock |
|---------|-----|----------|------|------|
| **Red Team Attacks** | 50 | 125 | 250+ | Simulated |
| **WAF Compliance Checks** | 5 | 11 | 20+ | Simulated |
| **Quality Evaluations** | 40 | 100 | 200+ | Simulated |
| **Safety Prompts** | 50 | 150 | 300+ | Simulated |
| **Monthly Cost** | $50-100 | $200-400 | $500-800 | $0 |
| **Execution Time** | 2-4 min | 5-10 min | 10-25 min | 1-2 min |

---

## 🏗️ **Architecture**

Each test includes:

1. **WAF & Security Compliance**
   - Azure Resource Graph queries
   - Security baseline validation
   - Compliance scoring

2. **Quality & Safety Evaluations**  
   - Azure AI Foundry quality metrics
   - Azure AI Content Safety filtering
   - Toxicity detection

3. **Red Team Security Testing**
   - 8 attack categories
   - Prompt injection, jailbreaking, data exfiltration
   - Advanced evasion techniques

4. **Automated Mitigations**
   - Vulnerability analysis
   - Automated fixes
   - Manual action recommendations

5. **Comprehensive Reporting**
   - JSON reports with detailed metrics
   - Pass/fail criteria validation
   - Production readiness assessment

---

## 🔧 **Troubleshooting**

### **Azure Authentication Issues**
```bash
# Re-authenticate with Azure
az login

# Check current account
az account show

# Set correct subscription
az account set --subscription "your-subscription-id"
```

### **Missing Dependencies**
```bash
# Install all requirements
pip install -r requirements.txt

# Or install core packages individually
pip install azure-identity azure-ai-evaluation azure-cognitiveservices-language-textanalytics
```

### **Cost Concerns**
```bash
# Start with mock testing (free)
python test_challenge2_mock.py

# Then try low intensity
python test_challenge2_low_intensity.py

# Monitor costs in Azure portal before running higher intensities
```

---

## 📈 **Next Steps**

1. **Start with Mock Testing** - Validate setup without costs
2. **Run Low Intensity** - Quick production validation
3. **Scale to Moderate** - Regular monitoring and validation
4. **Full Intensity for Certification** - Comprehensive security validation
5. **Implement CI/CD** - Automated testing with mock version

---

## 🏆 **Success Criteria**

All tests validate against Microsoft Challenge 2 requirements:

- ✅ **WAF Compliance** ≥ 70-80% (varies by intensity)
- ✅ **Quality Score** ≥ 90-95% (varies by intensity)  
- ✅ **Safety Score** = 100% (zero toxic outputs)
- ✅ **Zero Critical Vulnerabilities**
- ✅ **Effective Mitigations** ≥ 50-70% (varies by intensity)

**Result Categories:**
- 🏆 **EXCELLENT** - All criteria exceeded
- ✅ **PASSED** - All criteria met
- ⚠️ **CONDITIONAL** - Most criteria met, minor issues
- ❌ **FAILED** - Critical criteria not met

---

## 📞 **Support**

For issues or questions:
1. Check troubleshooting section above
2. Verify Azure setup and credentials  
3. Start with mock testing to validate code
4. Review generated reports in `./reports/` directory
5. Check Azure portal for service health and quotas