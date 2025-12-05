#!/usr/bin/env python3
"""
Azure Resource Graph Integration para WAF Compliance
====================================================

Script for integration with Azure Resource Graph queries according to Challenge 2.
Baseado no script checklist_graph.sh da Microsoft para AI Landing Zone.

Funcionalidades:
- Executa queries do Azure Resource Graph
- Analisa compliance com WAF AI Landing Zone
- Generates reports compatible with Challenge 2 spreadsheets
- Integra com Enhanced Red Team results
"""

import os
import json
import asyncio
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

try:
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.resourcegraph import ResourceGraphClient
    from azure.mgmt.resourcegraph.models import QueryRequest
except ImportError as e:
    print(f"❌ Erro ao importar Azure SDK: {e}")
    print("💡 Execute: pip install azure-mgmt-resourcegraph")

@dataclass
class WAFCheckResult:
    """WAF verification result"""
    check_id: str
    category: str
    subcategory: str
    description: str
    status: str  # PASS, FAIL, WARNING, NOT_APPLICABLE
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    resource_count: int
    compliant_resources: int
    non_compliant_resources: int
    recommendations: List[str]
    query_results: Dict[str, Any]

class AzureWAFChecker:
    """
    Verificador de compliance WAF usando Azure Resource Graph
    """
    
    def __init__(self):
        self.credential = DefaultAzureCredential()
        self.resource_graph_client = ResourceGraphClient(self.credential)
        self.subscription_ids = self._get_subscription_ids()
        self.logger = logging.getLogger(__name__)
        
    def _get_subscription_ids(self) -> List[str]:
        """Get available subscription IDs"""
        # Por simplicidade, usando subscription do ambiente
        # In production, could list all subscriptions
        subscription_id = os.getenv('AZURE_SUBSCRIPTION_ID')
        if subscription_id:
            return [subscription_id]
        return []
    
    def get_ai_landing_zone_queries(self) -> Dict[str, Dict[str, str]]:
        """
        Retorna queries do Azure Resource Graph para AI Landing Zone
        Baseado no checklist da Microsoft
        """
        return {
            "network_topology": {
                "outbound_network_access": '''
                Resources
                | where type =~ "Microsoft.CognitiveServices/accounts"
                | extend networkRules = properties.networkAcls
                | extend allowedOutbound = networkRules.defaultAction
                | project name, resourceGroup, allowedOutbound, networkRules
                | where allowedOutbound != "Deny"
                ''',
                
                "private_endpoints": '''
                Resources
                | where type =~ "Microsoft.Network/privateEndpoints"
                | join kind=inner (
                    Resources
                    | where type =~ "Microsoft.CognitiveServices/accounts"
                    | project cognitiveServiceId = id, cognitiveServiceName = name
                ) on $left.properties.privateLinkServiceConnections[0].properties.privateLinkServiceId == $right.cognitiveServiceId
                | project name, resourceGroup, cognitiveServiceName, status = properties.provisioningState
                ''',
                
                "vnet_integration": '''
                Resources
                | where type =~ "Microsoft.Web/sites"
                | extend vnetIntegration = properties.virtualNetworkSubnetId
                | project name, resourceGroup, vnetIntegration
                | where isempty(vnetIntegration)
                '''
            },
            
            "identity_access": {
                "managed_identity": '''
                Resources
                | where type =~ "Microsoft.Web/sites" or type =~ "Microsoft.ContainerInstance/containerGroups"
                | extend managedIdentity = identity.type
                | project name, resourceGroup, type, managedIdentity
                | where isempty(managedIdentity) or managedIdentity != "SystemAssigned"
                ''',
                
                "rbac_assignments": '''
                AuthorizationResources
                | where type =~ "Microsoft.Authorization/roleAssignments"
                | extend principalType = properties.principalType
                | extend roleDefinitionId = properties.roleDefinitionId
                | project principalType, roleDefinitionId, scope
                | where principalType == "User"
                | summarize count() by roleDefinitionId
                ''',
                
                "keyvault_integration": '''
                Resources
                | where type =~ "Microsoft.KeyVault/vaults"
                | extend accessPolicies = properties.accessPolicies
                | project name, resourceGroup, accessPolicies
                | extend hasApplicationInsightsKey = array_length(accessPolicies) > 0
                '''
            },
            
            "data_protection": {
                "encryption_at_rest": '''
                Resources
                | where type =~ "Microsoft.CognitiveServices/accounts"
                | extend encryption = properties.encryption
                | project name, resourceGroup, encryption
                | where isempty(encryption) or encryption.keySource != "Microsoft.KeyVault"
                ''',
                
                "storage_encryption": '''
                Resources
                | where type =~ "Microsoft.Storage/storageAccounts"
                | extend encryption = properties.encryption
                | project name, resourceGroup, encryption
                | where encryption.services.blob.enabled != true or encryption.services.file.enabled != true
                ''',
                
                "data_retention": '''
                Resources
                | where type =~ "Microsoft.Insights/components"
                | extend retentionInDays = properties.RetentionInDays
                | project name, resourceGroup, retentionInDays
                | where retentionInDays > 90
                '''
            },
            
            "monitoring_logging": {
                "app_insights_enabled": '''
                Resources
                | where type =~ "Microsoft.Web/sites"
                | extend appInsightsKey = properties.siteConfig.appSettings
                | project name, resourceGroup, appInsightsKey
                | extend hasAppInsights = array_length(appInsightsKey) > 0
                | where hasAppInsights != true
                ''',
                
                "diagnostic_settings": '''
                Resources
                | where type =~ "Microsoft.CognitiveServices/accounts"
                | join kind=leftouter (
                    Resources
                    | where type =~ "Microsoft.Insights/diagnosticSettings"
                    | extend targetResourceId = properties.storageAccountId
                    | project diagnosticSettingName = name, targetResourceId
                ) on $left.id == $right.targetResourceId
                | where isempty(diagnosticSettingName)
                ''',
                
                "security_alerts": '''
                SecurityResources
                | where type =~ "Microsoft.Security/assessments"
                | extend severity = properties.metadata.severity
                | extend status = properties.status.code
                | project name, severity, status, resourceGroup
                | where status == "Unhealthy" and severity == "High"
                '''
            }
        }
    
    async def run_waf_compliance_check(self) -> List[WAFCheckResult]:
        """Execute complete WAF compliance verification"""
        self.logger.info("Starting WAF compliance verification")
        
        results = []
        queries = self.get_ai_landing_zone_queries()
        
        for category, subcategory_queries in queries.items():
            for subcategory, query in subcategory_queries.items():
                try:
                    result = await self._execute_resource_graph_query(
                        category, subcategory, query
                    )
                    results.append(result)
                except Exception as e:
                    self.logger.error(f"Erro na query {category}.{subcategory}: {e}")
                    
                    # Cria resultado de erro
                    error_result = WAFCheckResult(
                        check_id=f"{category}_{subcategory}",
                        category=category,
                        subcategory=subcategory,
                        description=f"Query execution failed: {str(e)}",
                        status="FAIL",
                        severity="HIGH",
                        resource_count=0,
                        compliant_resources=0,
                        non_compliant_resources=0,
                        recommendations=[f"Fix query execution error: {str(e)}"],
                        query_results={}
                    )
                    results.append(error_result)
        
        return results
    
    async def _execute_resource_graph_query(self, category: str, subcategory: str, query: str) -> WAFCheckResult:
        """Execute a specific query in Azure Resource Graph"""
        
        try:
            # Prepara request
            request = QueryRequest(
                query=query,
                subscriptions=self.subscription_ids
            )
            
            # Executa query
            response = self.resource_graph_client.resources(request)
            
            # Analisa resultados
            data = response.data
            resource_count = len(data) if data else 0
            
            # Determina compliance baseado na query
            non_compliant_resources = resource_count  # Assume results = non-compliance
            compliant_resources = 0  # Em queries WAF, sem resultado = compliance
            
            # Determina status
            if resource_count == 0:
                status = "PASS"
                severity = "LOW"
            elif resource_count < 5:
                status = "WARNING"
                severity = "MEDIUM"
            else:
                status = "FAIL"
                severity = "HIGH"
            
            # Generate recommendations
            recommendations = self._generate_waf_recommendations(category, subcategory, resource_count)
            
            return WAFCheckResult(
                check_id=f"{category}_{subcategory}",
                category=category,
                subcategory=subcategory,
                description=self._get_check_description(category, subcategory),
                status=status,
                severity=severity,
                resource_count=resource_count,
                compliant_resources=compliant_resources,
                non_compliant_resources=non_compliant_resources,
                recommendations=recommendations,
                query_results={"data": data, "count": resource_count}
            )
            
        except Exception as e:
            raise Exception(f"Failed to execute query for {category}.{subcategory}: {str(e)}")
    
    def _generate_waf_recommendations(self, category: str, subcategory: str, issue_count: int) -> List[str]:
        """Generate recommendations based on results"""
        if issue_count == 0:
            return ["Configuration is compliant with WAF recommendations"]
        
        recommendations_map = {
            ("network_topology", "outbound_network_access"): [
                "Configure network access controls to deny by default",
                "Implement IP filtering and firewall rules",
                "Use private endpoints for sensitive services"
            ],
            ("identity_access", "managed_identity"): [
                "Enable system-assigned managed identity",
                "Remove unnecessary service principals",
                "Implement least-privilege access"
            ],
            ("data_protection", "encryption_at_rest"): [
                "Enable encryption at rest for all data stores",
                "Use customer-managed keys where appropriate",
                "Implement data classification policies"
            ],
            ("monitoring_logging", "app_insights_enabled"): [
                "Enable Application Insights for all web applications",
                "Configure diagnostic settings",
                "Set up security alerts and monitoring"
            ]
        }
        
        key = (category, subcategory)
        return recommendations_map.get(key, [
            f"Review and fix {issue_count} non-compliant resources",
            "Follow WAF security best practices",
            "Implement monitoring and alerting"
        ])
    
    def _get_check_description(self, category: str, subcategory: str) -> str:
        """Returns verification description"""
        descriptions = {
            ("network_topology", "outbound_network_access"): "Verify outbound network access is properly restricted",
            ("network_topology", "private_endpoints"): "Check for private endpoint configuration",
            ("network_topology", "vnet_integration"): "Verify VNet integration for web apps",
            ("identity_access", "managed_identity"): "Check for managed identity usage",
            ("identity_access", "rbac_assignments"): "Review RBAC role assignments",
            ("identity_access", "keyvault_integration"): "Verify Key Vault integration",
            ("data_protection", "encryption_at_rest"): "Check encryption at rest configuration",
            ("data_protection", "storage_encryption"): "Verify storage account encryption",
            ("data_protection", "data_retention"): "Review data retention policies",
            ("monitoring_logging", "app_insights_enabled"): "Check Application Insights enablement",
            ("monitoring_logging", "diagnostic_settings"): "Verify diagnostic settings configuration",
            ("monitoring_logging", "security_alerts"): "Review security assessment alerts"
        }
        
        key = (category, subcategory)
        return descriptions.get(key, f"WAF compliance check for {category}.{subcategory}")
    
    def generate_waf_compliance_report(self, results: List[WAFCheckResult]) -> Dict[str, Any]:
        """Gera relatório de compliance WAF"""
        
        total_checks = len(results)
        passed_checks = len([r for r in results if r.status == "PASS"])
        failed_checks = len([r for r in results if r.status == "FAIL"])
        warning_checks = len([r for r in results if r.status == "WARNING"])
        
        compliance_score = (passed_checks / total_checks) * 100 if total_checks > 0 else 0
        
        # Categoriza por severidade
        critical_issues = [r for r in results if r.severity == "CRITICAL"]
        high_issues = [r for r in results if r.severity == "HIGH"]
        medium_issues = [r for r in results if r.severity == "MEDIUM"]
        
        # Determina postura geral
        if len(critical_issues) > 0 or compliance_score < 50:
            posture = "POOR"
        elif len(high_issues) > 2 or compliance_score < 70:
            posture = "FAIR"
        elif compliance_score < 90:
            posture = "GOOD"
        else:
            posture = "EXCELLENT"
        
        return {
            "scan_timestamp": datetime.now().isoformat(),
            "total_checks": total_checks,
            "passed_checks": passed_checks,
            "failed_checks": failed_checks,
            "warning_checks": warning_checks,
            "compliance_score": compliance_score,
            "security_posture": posture,
            "critical_issues": len(critical_issues),
            "high_issues": len(high_issues),
            "medium_issues": len(medium_issues),
            "results_by_category": self._group_results_by_category(results),
            "top_recommendations": self._get_top_recommendations(results),
            "challenge_2_alignment": {
                "waf_security_compliance": compliance_score >= 70,
                "ai_landing_zone_compliant": len(critical_issues) == 0,
                "ready_for_production": posture in ["GOOD", "EXCELLENT"]
            }
        }
    
    def _group_results_by_category(self, results: List[WAFCheckResult]) -> Dict[str, List[Dict[str, Any]]]:
        """Agrupa resultados por categoria"""
        categories = {}
        
        for result in results:
            if result.category not in categories:
                categories[result.category] = []
            
            categories[result.category].append({
                "subcategory": result.subcategory,
                "status": result.status,
                "severity": result.severity,
                "resource_count": result.resource_count,
                "non_compliant_count": result.non_compliant_resources,
                "recommendations": result.recommendations
            })
        
        return categories
    
    def _get_top_recommendations(self, results: List[WAFCheckResult]) -> List[str]:
        """Extrai principais recomendações"""
        all_recommendations = []
        
        # Prioriza recomendações de issues críticos e high
        for result in results:
            if result.severity in ["CRITICAL", "HIGH"] and result.status != "PASS":
                all_recommendations.extend(result.recommendations)
        
        # Remove duplicatas e limita a 10
        unique_recommendations = list(set(all_recommendations))
        return unique_recommendations[:10]
    
    def export_to_csv(self, results: List[WAFCheckResult], output_file: str) -> None:
        """Exporta resultados para CSV compatível com Challenge 2 spreadsheet"""
        import csv
        
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Cabeçalho compatível com WAF checklist
            writer.writerow([
                'Check ID', 'Category', 'Subcategory', 'Description', 
                'Status', 'Severity', 'Resource Count', 'Non-Compliant', 
                'Compliance %', 'Top Recommendation'
            ])
            
            for result in results:
                compliance_pct = ((result.resource_count - result.non_compliant_resources) / 
                                max(result.resource_count, 1)) * 100
                
                writer.writerow([
                    result.check_id,
                    result.category.replace('_', ' ').title(),
                    result.subcategory.replace('_', ' ').title(),
                    result.description,
                    result.status,
                    result.severity,
                    result.resource_count,
                    result.non_compliant_resources,
                    f"{compliance_pct:.1f}%",
                    result.recommendations[0] if result.recommendations else "No recommendations"
                ])

async def main():
    """Função principal do WAF Checker"""
    print("🏗️ Azure WAF Compliance Checker - Challenge 2")
    print("=" * 60)
    
    try:
        # Inicializa checker
        checker = AzureWAFChecker()
        
        # Executa verificações
        print("📊 Executando verificações WAF...")
        results = await checker.run_waf_compliance_check()
        
        # Gera relatório
        report = checker.generate_waf_compliance_report(results)
        
        # Salva resultados
        output_dir = Path("./reports/waf_compliance")
        output_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Salva JSON
        json_file = output_dir / f"waf_compliance_{timestamp}.json"
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump({
                "report": report,
                "detailed_results": [result.__dict__ for result in results]
            }, f, indent=2, ensure_ascii=False)
        
        # Salva CSV
        csv_file = output_dir / f"waf_compliance_{timestamp}.csv"
        checker.export_to_csv(results, str(csv_file))
        
        # Exibe resumo
        print(f"\\n📋 WAF COMPLIANCE SUMMARY:")
        print(f"   • Total Checks: {report['total_checks']}")
        print(f"   • Compliance Score: {report['compliance_score']:.1f}%")
        print(f"   • Security Posture: {report['security_posture']}")
        print(f"   • Critical Issues: {report['critical_issues']}")
        print(f"   • High Issues: {report['high_issues']}")
        
        print(f"\\n🎯 CHALLENGE 2 STATUS:")
        alignment = report['challenge_2_alignment']
        print(f"   • WAF Security Compliant: {'✅' if alignment['waf_security_compliance'] else '❌'}")
        print(f"   • AI Landing Zone Ready: {'✅' if alignment['ai_landing_zone_compliant'] else '❌'}")
        print(f"   • Production Ready: {'✅' if alignment['ready_for_production'] else '❌'}")
        
        print(f"\\n📄 Reports saved:")
        print(f"   • JSON: {json_file}")
        print(f"   • CSV: {csv_file}")
        
        # Exit code baseado em compliance
        if report['compliance_score'] >= 70 and report['critical_issues'] == 0:
            return 0
        else:
            return 1
            
    except Exception as e:
        print(f"❌ Erro durante verificação WAF: {e}")
        return 1

if __name__ == "__main__":
    exit_code = asyncio.run(main())