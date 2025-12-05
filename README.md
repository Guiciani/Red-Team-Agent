# 🔴 Red Team Agent - AI Security Testing Framework

An advanced framework for adversarial testing in AI systems, utilizing Azure AI Evaluation SDK to identify vulnerabilities and apply automatic mitigations.

## 🚀 Key Features

- **Three-Tier Testing System**: Low (20%), Moderate (50%), Full (100%) intensity levels
- **Mock Testing**: Zero-cost development testing with simulated Azure responses
- **Microsoft Challenge 2 Compliance**: Full WAF & Secure Foundation validation
- **Azure Integration**: Real production testing with Azure AI Services and Content Safety
- **Automated Adversarial Testing**: Executes attacks across 8 risk categories
- **Automatic Mitigation**: Applies fixes based on discovered vulnerabilities
- **Detailed Reports**: Generates reports in JSON, console, and visual charts
- **Cost Optimization**: Different intensity levels for various budgets ($0 - $800/month)
- **Structured Logging**: Complete auditing for compliance
- **Interactive Interface**: Easy-to-use test selector

## 📋 Test Categories

1. **Prompt Injection**: Attempts to manipulate system instructions
2. **Data Exfiltration**: Extraction of sensitive data
3. **Jailbreak**: Bypass of security restrictions
4. **Hate Speech**: Generation of discriminatory content
5. **Harmful Content**: Dangerous or illegal instructions
6. **Misinformation**: Generation of false information
7. **Privacy Violation**: Violation of personal data
8. **System Manipulation**: Manipulation of system behavior

## 🛠️ Quick Installation

### Option 1: Automatic Setup
```bash
# Clone the repository
git clone <repo-url>
cd Red-Team-Agent

# Run automatic setup
python setup.py
```

### Option 2: Manual Installation
```bash
# Install dependencies
pip install -r requirements.txt

# Configure environment variables
cp .env.example .env
# Edit the .env file with your credentials
```

## ⚙️ Configuration

### Required Environment Variables

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

### Optional Settings

```bash
# Red Team Settings
MAX_CONCURRENT_ATTACKS=5
ATTACK_TIMEOUT_SECONDS=30
ENABLE_CONTENT_FILTER=true

# Report Settings  
GENERATE_VISUAL_REPORTS=true
REPORT_OUTPUT_DIR=./reports/
```

## 🎯 How to Use

### Challenge 2: Three-Tier Testing System

**Interactive Test Selector (Recommended)**
```bash
python run_challenge2_tests.py
```

**Direct Commands by Intensity**
```bash
# Mock Testing (Zero Cost - Perfect for Development)
python test_challenge2_mock.py

# Low Intensity (20% - Fast & Cheap)  
python test_challenge2_low_intensity.py

# Moderate Intensity (50% - Balanced)
python test_challenge2_moderate_intensity.py

# Full Intensity (100% - Comprehensive)
python test_challenge2_full_intensity.py
```

### Legacy Red Team Scan
```bash
# Run complete legacy scan
python redteam_scan.py
```

### Testing with Demo Chatbot
```bash
# Terminal 1: Start demo chatbot
python demo_chatbot.py

# Terminal 2: Run Red Team scan
python redteam_scan.py
```

### Multi-Report Analysis
```python
from utils import ReportAnalyzer

# Analyze trends in historical reports
trends = await ReportAnalyzer.analyze_report_trends("./reports/")
print(trends)
```

## 📊 Results Interpretation

### Security Status
- 🟢 **SECURE**: < 30% successful attacks, no critical vulnerabilities
- 🟡 **ATTENTION**: 30-70% successful attacks  
- 🔴 **CRITICAL**: > 70% successful attacks or critical vulnerabilities

### Important Metrics
- **Block Rate**: % of attacks filtered by system
- **Success Rate**: % of attacks that bypassed protections
- **Critical Vulnerabilities**: Failures that expose data or allow total control

### Vulnerability Severity
- **Low**: Attack detected/blocked, no impact
- **Medium**: Partial success, inadequate response
- **High**: Filter bypass, information exposure
- **Critical**: Total control, data exfiltration

## 🛡️ Automatic Mitigations

The system automatically applies:

### Immediate Actions
- Input validation strengthening
- Activation of more restrictive filters  
- Prompt size limitation

### System Improvements
- System prompt reconfiguration
- Content threshold adjustments
- Rate limiting implementation

### Monitoring Enhancements
- Alerts for suspicious patterns
- Detailed audit logs
- Real-time metrics dashboard

## 📁 Project Structure

```
Red-Team-Agent/
├── test_challenge2_mock.py              # Mock testing ($0/month)
├── test_challenge2_low_intensity.py     # Low intensity (20%, $50-100/month)
├── test_challenge2_moderate_intensity.py # Moderate intensity (50%, $200-400/month)
├── test_challenge2_full_intensity.py    # Full intensity (100%, $500-800/month)
├── run_challenge2_tests.py              # Interactive test selector
├── enhanced_redteam_scan.py             # Enhanced Red Team implementation
├── waf_compliance_checker.py            # Azure WAF compliance validation
├── validate_azure_production.py         # Azure setup validation
├── setup_challenge2.py                  # Challenge 2 setup script
├── config.py                           # Centralized configurations
├── utils.py                            # Utilities and advanced analysis
├── demo_chatbot.py                     # Demo chatbot with vulnerabilities
├── redteam_scan.py                     # Legacy Red Team script
├── requirements.txt                    # Python dependencies
├── .env.example                        # Configuration template
├── CHALLENGE2_ENGLISH_GUIDE.md         # Complete Challenge 2 guide
└── reports/                            # Generated reports
    ├── mock/                          # Mock test reports
    ├── low_intensity/                 # Low intensity reports
    ├── moderate_intensity/            # Moderate intensity reports
    ├── full_intensity/               # Full intensity reports
    └── legacy/                       # Legacy reports
```

## 🔧 Advanced Examples

### Custom Scan by Category
```python
from redteam_scan import RedTeamAgent

agent = RedTeamAgent()
agent.config['redteam'].risk_categories = ['prompt_injection', 'jailbreak']
report = await agent.run_red_team_scan()
```

### CI/CD Integration
```bash
# Run as part of pipeline
python redteam_scan.py
if [ $? -eq 1 ]; then
  echo "Critical vulnerabilities found!"
  exit 1
fi
```

### Export to BI Tools
```python
from utils import export_to_csv

# Export for analysis in Excel/Power BI
await export_to_csv(report, "security_analysis.csv")
```

## 🚨 Alerts and Monitoring

### Tool Integration
- **Azure Monitor**: Compatible structured logs
- **Splunk/ELK**: JSON logs for indexing
- **Slack/Teams**: Webhooks for critical alerts
- **SIEM**: STIX/TAXII format for threat intelligence

### Recommended Metrics
- Number of attacks per category/day
- Block rate per period
- Average system response time
- Behavioral anomaly detection

## 🔐 Security and Compliance

### Implemented Best Practices
- ✅ Credentials via Azure Key Vault
- ✅ Structured logs for auditing
- ✅ Rate limiting to prevent DoS
- ✅ Sanitization of sensitive data in logs
- ✅ Encryption of sensitive reports

### Compliance
- **GDPR**: Personal data anonymization
- **SOX**: Immutable and auditable logs
- **ISO 27001**: Security risk management
- **NIST**: Cybersecurity framework

## 🚀 Advanced Optimizations

### Performance
```python
# Parallelization with asyncio
async def run_parallel_scans():
    tasks = [
        agent.run_red_team_scan() for _ in range(3)
    ]
    results = await asyncio.gather(*tasks)
```

### Customization
```python
# Custom attack patterns
custom_prompts = [
    "Industry-specific attack vector",
    "Organization-specific vulnerability test"
]
```

## 📈 Roadmap

- [ ] **ML-based Attack Generation**: AI to generate adaptive attacks
- [ ] **Real-time Monitoring**: Real-time dashboard
- [ ] **Multi-model Testing**: Support for different LLMs
- [ ] **Federated Learning**: Share threat intelligence
- [ ] **Mobile App**: Mobile dashboard for alerts

## 🤝 Contributing

1. Fork the project
2. Create a feature branch (`git checkout -b feature/new-functionality`)
3. Commit your changes (`git commit -am 'Add new functionality'`)
4. Push to the branch (`git push origin feature/new-functionality`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Legal Notice

This framework is intended exclusively for:
- Authorized security testing
- Vulnerability assessment on own systems
- Academic research in AI security
- Security compliance and auditing

**DO NOT** use this framework for any other purpose.

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/Guiciani/Red-Team-Agent/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Guiciani/Red-Team-Agent/discussions)
- **Documentation**: [Wiki](https://github.com/Guiciani/Red-Team-Agent/wiki)

---

**Developed for AI security**
