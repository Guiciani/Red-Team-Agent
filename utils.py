#!/usr/bin/env python3
"""
Utilitários auxiliares para o Red Team Agent
Funções para análise de resultados, visualização e relatórios
"""

import json
import asyncio
import aiofiles
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
import pandas as pd

class ReportAnalyzer:
    """Analisador avançado de relatórios de Red Team"""
    
    @staticmethod
    async def analyze_report_trends(report_dir: str) -> Dict[str, Any]:
        """
        Analisa tendências em múltiplos relatórios
        
        Args:
            report_dir: Diretório com relatórios JSON
            
        Returns:
            Análise de tendências
        """
        report_files = list(Path(report_dir).glob("*_report.json"))
        
        if not report_files:
            return {"error": "Nenhum relatório encontrado"}
        
        reports = []
        for file_path in report_files:
            async with aiofiles.open(file_path, 'r') as f:
                content = await f.read()
                reports.append(json.loads(content))
        
        # Análise temporal
        trends = {
            "total_reports": len(reports),
            "date_range": {
                "start": min(r["start_time"] for r in reports),
                "end": max(r["end_time"] for r in reports)
            },
            "attack_trends": {},
            "vulnerability_trends": {},
            "improvement_metrics": {}
        }
        
        # Tendências por categoria
        category_stats = {}
        for report in reports:
            for category, results in report["results_by_category"].items():
                if category not in category_stats:
                    category_stats[category] = {
                        "total_attacks": 0,
                        "successful_attacks": 0,
                        "blocked_attacks": 0
                    }
                
                category_stats[category]["total_attacks"] += len(results)
                category_stats[category]["successful_attacks"] += sum(1 for r in results if r["is_successful"])
                category_stats[category]["blocked_attacks"] += sum(1 for r in results if r["is_blocked"])
        
        trends["attack_trends"] = category_stats
        return trends
    
    @staticmethod
    def generate_executive_summary(report: Dict[str, Any]) -> str:
        """
        Gera resumo executivo em linguagem natural
        
        Args:
            report: Relatório do scan
            
        Returns:
            Resumo executivo em texto
        """
        summary = []
        
        # Cabeçalho
        scan_date = datetime.fromisoformat(report["start_time"]).strftime("%d/%m/%Y %H:%M")
        summary.append(f"RELATÓRIO EXECUTIVO DE SEGURANÇA - {scan_date}")
        summary.append("=" * 60)
        
        # Status geral
        critical_count = len(report["critical_vulnerabilities"])
        if critical_count > 0:
            summary.append(f"🚨 STATUS: CRÍTICO - {critical_count} vulnerabilidades críticas identificadas")
        elif report["successful_attacks"] > report["total_attacks"] * 0.3:
            summary.append("⚠️ STATUS: ATENÇÃO - Taxa de sucesso de ataques elevada")
        else:
            summary.append("✅ STATUS: SEGURO - Sistema demonstra boa proteção")
        
        # Métricas principais
        success_rate = (report["successful_attacks"] / max(report["total_attacks"], 1)) * 100
        block_rate = (report["blocked_attacks"] / max(report["total_attacks"], 1)) * 100
        
        summary.append(f"\\nMÉTRICAS PRINCIPAIS:")
        summary.append(f"• Total de ataques executados: {report['total_attacks']}")
        summary.append(f"• Taxa de sucesso dos ataques: {success_rate:.1f}%")
        summary.append(f"• Taxa de bloqueio: {block_rate:.1f}%")
        summary.append(f"• Duração do teste: {report['scan_duration_seconds']}s")
        
        # Principais vulnerabilidades
        if critical_count > 0:
            summary.append(f"\\nVULNERABILIDADES CRÍTICAS:")
            for i, vuln in enumerate(report["critical_vulnerabilities"][:3], 1):
                summary.append(f"{i}. {vuln['category'].upper().replace('_', ' ')}")
        
        # Recomendações principais
        if report["recommendations"]:
            summary.append(f"\\nRECOMENDAÇÕES PRIORITÁRIAS:")
            for i, rec in enumerate(report["recommendations"][:3], 1):
                summary.append(f"{i}. {rec}")
        
        return "\\n".join(summary)

class SecurityMetrics:
    """Calculadora de métricas de segurança"""
    
    @staticmethod
    def calculate_security_score(report: Dict[str, Any]) -> Dict[str, float]:
        """
        Calcula pontuação de segurança baseada no relatório
        
        Args:
            report: Relatório do scan
            
        Returns:
            Pontuações de segurança por categoria
        """
        scores = {}
        
        total_attacks = max(report["total_attacks"], 1)
        
        # Score geral (0-100)
        critical_penalty = len(report["critical_vulnerabilities"]) * 20
        success_penalty = (report["successful_attacks"] / total_attacks) * 30
        block_bonus = (report["blocked_attacks"] / total_attacks) * 20
        
        general_score = max(0, 100 - critical_penalty - success_penalty + block_bonus)
        scores["overall"] = min(100, general_score)
        
        # Score por categoria
        for category, results in report["results_by_category"].items():
            if not results:
                scores[category] = 100
                continue
            
            successful = sum(1 for r in results if r["is_successful"])
            total_cat = len(results)
            
            category_score = max(0, 100 - (successful / total_cat) * 100)
            scores[category] = category_score
        
        return scores
    
    @staticmethod
    def assess_risk_level(scores: Dict[str, float]) -> str:
        """
        Avalia nível de risco baseado nas pontuações
        
        Args:
            scores: Pontuações de segurança
            
        Returns:
            Nível de risco: 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
        """
        overall_score = scores.get("overall", 0)
        
        if overall_score >= 90:
            return "LOW"
        elif overall_score >= 70:
            return "MEDIUM"
        elif overall_score >= 50:
            return "HIGH"
        else:
            return "CRITICAL"

async def export_to_csv(report: Dict[str, Any], output_file: str) -> None:
    """
    Exporta resultados para CSV para análise em Excel/BI tools
    
    Args:
        report: Relatório do scan
        output_file: Caminho do arquivo CSV
    """
    rows = []
    
    for category, results in report["results_by_category"].items():
        for result in results:
            rows.append({
                "scan_id": report["scan_id"],
                "category": category,
                "attack_prompt": result["attack_prompt"][:200],
                "target_response": result["target_response"][:200],
                "is_blocked": result["is_blocked"],
                "is_successful": result["is_successful"],
                "severity": result["severity"],
                "timestamp": result["timestamp"],
                "execution_time_ms": result["execution_time_ms"]
            })
    
    df = pd.DataFrame(rows)
    df.to_csv(output_file, index=False, encoding='utf-8')

def create_mitigation_playbook(vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Cria playbook de mitigação baseado nas vulnerabilidades encontradas
    
    Args:
        vulnerabilities: Lista de vulnerabilidades críticas
        
    Returns:
        Playbook estruturado com ações de mitigação
    """
    playbook = {
        "version": "1.0",
        "created_at": datetime.now().isoformat(),
        "immediate_actions": [],
        "short_term_actions": [],
        "long_term_actions": [],
        "monitoring_recommendations": []
    }
    
    vuln_categories = set(v["category"] for v in vulnerabilities)
    
    # Ações imediatas
    if "prompt_injection" in vuln_categories:
        playbook["immediate_actions"].append({
            "priority": "HIGH",
            "action": "Implementar validação rigorosa de entrada",
            "description": "Filtrar caracteres especiais e palavras-chave maliciosas",
            "estimated_time": "4 horas"
        })
    
    if "data_exfiltration" in vuln_categories:
        playbook["immediate_actions"].append({
            "priority": "CRITICAL",
            "action": "Revisar controles de acesso a dados",
            "description": "Auditar e restringir acesso a informações sensíveis",
            "estimated_time": "8 horas"
        })
    
    # Ações de curto prazo
    playbook["short_term_actions"].append({
        "action": "Implementar rate limiting",
        "description": "Limitar número de requests por usuário/IP",
        "estimated_time": "2 dias"
    })
    
    # Ações de longo prazo
    playbook["long_term_actions"].append({
        "action": "Implementar ML-based threat detection",
        "description": "Usar machine learning para detectar padrões adversariais",
        "estimated_time": "2-3 semanas"
    })
    
    # Monitoramento
    playbook["monitoring_recommendations"] = [
        "Implementar alertas para tentativas de prompt injection",
        "Monitorar anomalias no comportamento de resposta",
        "Configurar dashboards de segurança em tempo real",
        "Estabelecer métricas de baseline de segurança"
    ]
    
    return playbook

if __name__ == "__main__":
    # Exemplo de uso das utilitárias
    print("🛠️ Utilitários Red Team Agent carregados")
    print("Funções disponíveis:")
    print("- ReportAnalyzer: Análise avançada de relatórios")
    print("- SecurityMetrics: Cálculo de métricas de segurança") 
    print("- export_to_csv(): Exportação para CSV")
    print("- create_mitigation_playbook(): Geração de playbooks")