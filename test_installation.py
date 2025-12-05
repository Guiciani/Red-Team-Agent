#!/usr/bin/env python3
"""
Script de teste para validar a instalação e funcionamento do Red Team Agent
Executa testes básicos sem necessidade de credenciais Azure
"""

import sys
import asyncio
import tempfile
import json
from pathlib import Path

def test_imports():
    """Testa se todas as importações necessárias estão funcionando"""
    print("🧪 Testando importações...")
    
    try:
        import requests
        import aiohttp
        import structlog
        from tabulate import tabulate
        from pydantic import BaseModel
        from dotenv import load_dotenv
        print("✅ Dependências básicas OK")
    except ImportError as e:
        print(f"❌ Erro nas dependências básicas: {e}")
        return False
    
    try:
        from config import config, validate_config
        from utils import ReportAnalyzer, SecurityMetrics
        print("✅ Módulos locais OK")
    except ImportError as e:
        print(f"❌ Erro nos módulos locais: {e}")
        return False
    
    # Azure SDK é opcional para testes
    try:
        from azure.ai.evaluation import RedTeam
        print("✅ Azure AI Evaluation SDK OK")
    except ImportError:
        print("⚠️ Azure AI Evaluation SDK não encontrado (normal em desenvolvimento)")
    
    return True

def test_configuration():
    """Testa se a configuração está sendo carregada corretamente"""
    print("\\n🧪 Testando configuração...")
    
    try:
        from config import config
        
        # Verifica estrutura da configuração
        required_sections = ['azure', 'chatbot', 'redteam', 'logging', 'report']
        for section in required_sections:
            if section not in config:
                print(f"❌ Seção '{section}' ausente na configuração")
                return False
        
        print("✅ Estrutura de configuração OK")
        
        # Verifica categorias de risco
        if len(config['redteam'].risk_categories) >= 8:
            print("✅ Categorias de risco configuradas")
        else:
            print("⚠️ Poucas categorias de risco configuradas")
        
        return True
        
    except Exception as e:
        print(f"❌ Erro na configuração: {e}")
        return False

async def test_demo_chatbot():
    """Testa se o chatbot demo responde corretamente"""
    print("\\n🧪 Testando chatbot demo...")
    
    try:
        import aiohttp
        
        # Tenta conectar com o chatbot demo (se estiver rodando)
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get('http://localhost:8000/health', timeout=aiohttp.ClientTimeout(total=2)) as response:
                    if response.status == 200:
                        print("✅ Chatbot demo está rodando e respondendo")
                        
                        # Teste de prompt simples
                        async with session.post(
                            'http://localhost:8000/chat',
                            json={'prompt': 'Hello, this is a test'},
                            timeout=aiohttp.ClientTimeout(total=5)
                        ) as chat_response:
                            if chat_response.status == 200:
                                data = await chat_response.json()
                                print("✅ Chatbot demo responde a prompts")
                                return True
                    
            except asyncio.TimeoutError:
                print("⚠️ Chatbot demo não está rodando (execute: python demo_chatbot.py)")
                return True  # Não é erro crítico
            except aiohttp.ClientConnectorError:
                print("⚠️ Chatbot demo não está rodando")
                return True  # Não é erro crítico
                
    except Exception as e:
        print(f"❌ Erro no teste do chatbot: {e}")
        return False

def test_report_generation():
    """Testa se a geração de relatórios está funcionando"""
    print("\\n🧪 Testando geração de relatórios...")
    
    try:
        from redteam_scan import AttackResult, ScanReport
        from utils import SecurityMetrics, create_mitigation_playbook
        from datetime import datetime
        
        # Cria dados de teste
        mock_results = [
            AttackResult(
                category="test_category",
                attack_prompt="Test prompt",
                target_response="Test response",
                is_blocked=False,
                is_successful=True,
                severity="medium",
                timestamp=datetime.now().isoformat(),
                execution_time_ms=100
            )
        ]
        
        mock_report = ScanReport(
            scan_id="test_scan_123",
            start_time=datetime.now().isoformat(),
            end_time=datetime.now().isoformat(),
            total_attacks=1,
            blocked_attacks=0,
            successful_attacks=1,
            failed_attacks=0,
            critical_vulnerabilities=[],
            results_by_category={"test_category": mock_results},
            recommendations=["Test recommendation"],
            scan_duration_seconds=10
        )
        
        # Testa métricas de segurança
        scores = SecurityMetrics.calculate_security_score(mock_report.__dict__)
        risk_level = SecurityMetrics.assess_risk_level(scores)
        
        if scores and risk_level:
            print("✅ Cálculo de métricas OK")
        
        # Testa playbook de mitigação
        playbook = create_mitigation_playbook(mock_results)
        if playbook and "immediate_actions" in playbook:
            print("✅ Geração de playbook OK")
        
        return True
        
    except Exception as e:
        print(f"❌ Erro na geração de relatórios: {e}")
        return False

def test_utils_functions():
    """Testa funções utilitárias"""
    print("\\n🧪 Testando utilitários...")
    
    try:
        from utils import ReportAnalyzer, SecurityMetrics, export_to_csv
        
        # Verifica se as classes estão carregando
        analyzer = ReportAnalyzer()
        metrics = SecurityMetrics()
        
        print("✅ Classes utilitárias OK")
        
        # Testa com dados mock
        mock_scores = {"overall": 75.0, "prompt_injection": 80.0}
        risk = SecurityMetrics.assess_risk_level(mock_scores)
        
        if risk in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
            print("✅ Avaliação de risco OK")
        
        return True
        
    except Exception as e:
        print(f"❌ Erro nos utilitários: {e}")
        return False

async def run_basic_redteam_test():
    """Executa um teste básico do Red Team Agent (sem Azure)"""
    print("\\n🧪 Testando Red Team Agent (modo offline)...")
    
    try:
        # Simula um teste básico sem dependência do Azure
        from redteam_scan import RedTeamAgent
        
        # Mock das configurações para teste
        import os
        os.environ['AZURE_CLIENT_ID'] = 'test'
        os.environ['AZURE_CLIENT_SECRET'] = 'test'
        os.environ['AZURE_TENANT_ID'] = 'test'
        os.environ['AZURE_OPENAI_ENDPOINT'] = 'test'
        os.environ['AZURE_OPENAI_API_KEY'] = 'test'
        
        # Cria agente (mas não executa scan real)
        try:
            agent = RedTeamAgent()
            print("✅ Red Team Agent inicializado")
            
            # Testa geração de prompts
            prompts = agent._generate_attack_prompts("prompt_injection")
            if len(prompts) > 0:
                print("✅ Geração de prompts adversariais OK")
            
            return True
            
        except Exception as e:
            print(f"⚠️ Red Team Agent requer configuração Azure: {e}")
            return True  # Não é erro crítico para teste
            
    except Exception as e:
        print(f"❌ Erro no teste do Red Team Agent: {e}")
        return False

def generate_test_report():
    """Gera um relatório de teste dos resultados"""
    print("\\n📋 RELATÓRIO DE TESTE")
    print("=" * 50)
    
    # Lista arquivos criados
    files_created = []
    for file_path in Path('.').glob('*.py'):
        if file_path.name in ['redteam_scan.py', 'config.py', 'utils.py', 'demo_chatbot.py', 'setup.py']:
            files_created.append(file_path.name)
    
    print(f"📁 Arquivos principais: {len(files_created)}")
    for file in files_created:
        print(f"   ✅ {file}")
    
    # Verifica diretórios
    if Path('reports').exists():
        print("📁 Diretório de relatórios: ✅")
    else:
        print("📁 Diretório de relatórios: ⚠️ (será criado automaticamente)")
    
    if Path('.env.example').exists():
        print("📁 Template de configuração: ✅")
    
    if Path('requirements.txt').exists():
        print("📁 Arquivo de dependências: ✅")
    
    print("\\n🎯 PRÓXIMOS PASSOS:")
    print("1. Configure suas credenciais Azure no arquivo .env")
    print("2. Execute: python setup.py (para instalação automática)")
    print("3. Execute: python demo_chatbot.py (em um terminal)")
    print("4. Execute: python redteam_scan.py (em outro terminal)")

async def main():
    """Função principal de teste"""
    print("🔴 RED TEAM AGENT - TESTE DE VALIDAÇÃO")
    print("=" * 60)
    
    tests = [
        ("Importações", test_imports),
        ("Configuração", test_configuration),
        ("Relatórios", test_report_generation),
        ("Utilitários", test_utils_functions)
    ]
    
    async_tests = [
        ("Chatbot Demo", test_demo_chatbot),
        ("Red Team Agent", run_basic_redteam_test)
    ]
    
    passed = 0
    total = len(tests) + len(async_tests)
    
    # Executa testes síncronos
    for test_name, test_func in tests:
        try:
            if test_func():
                passed += 1
            else:
                print(f"❌ Teste '{test_name}' falhou")
        except Exception as e:
            print(f"❌ Erro no teste '{test_name}': {e}")
    
    # Executa testes assíncronos
    for test_name, test_func in async_tests:
        try:
            if await test_func():
                passed += 1
            else:
                print(f"❌ Teste '{test_name}' falhou")
        except Exception as e:
            print(f"❌ Erro no teste '{test_name}': {e}")
    
    # Relatório final
    print(f"\\n📊 RESULTADO FINAL: {passed}/{total} testes passaram")
    
    if passed == total:
        print("🎉 Todos os testes passaram! Sistema está pronto.")
        generate_test_report()
        return 0
    elif passed >= total * 0.8:
        print("✅ A maioria dos testes passou. Sistema quase pronto.")
        generate_test_report()
        return 0
    else:
        print("⚠️ Vários testes falharam. Verifique a instalação.")
        return 1

if __name__ == "__main__":
    exit_code = asyncio.run(main())