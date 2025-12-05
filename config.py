"""
Centralized configuration for Red Team Agent
Manages environment variables and system configurations
"""

import os
import logging
from typing import Dict, List, Optional
from dataclasses import dataclass
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

@dataclass
class AzureConfig:
    """Azure configurations"""
    client_id: str = os.getenv("AZURE_CLIENT_ID", "")
    client_secret: str = os.getenv("AZURE_CLIENT_SECRET", "")
    tenant_id: str = os.getenv("AZURE_TENANT_ID", "")
    openai_endpoint: str = os.getenv("AZURE_OPENAI_ENDPOINT", "")
    openai_api_key: str = os.getenv("AZURE_OPENAI_API_KEY", "")
    deployment_name: str = os.getenv("AZURE_OPENAI_DEPLOYMENT_NAME", "gpt-4")

@dataclass
class ChatbotConfig:
    """Target chatbot configurations"""
    endpoint: str = os.getenv("CHATBOT_ENDPOINT", "http://localhost:8000/chat")
    auth_token: Optional[str] = os.getenv("CHATBOT_AUTH_TOKEN")
    timeout: int = int(os.getenv("CHATBOT_TIMEOUT", "30"))

@dataclass
class RedTeamConfig:
    """Red Team configurations"""
    max_concurrent_attacks: int = int(os.getenv("MAX_CONCURRENT_ATTACKS", "5"))
    attack_timeout: int = int(os.getenv("ATTACK_TIMEOUT_SECONDS", "30"))
    enable_content_filter: bool = os.getenv("ENABLE_CONTENT_FILTER", "true").lower() == "true"
    content_filter_threshold: str = os.getenv("CONTENT_FILTER_THRESHOLD", "medium")
    
    # Risk categories for testing
    risk_categories: List[str] = None
    
    def __post_init__(self):
        if self.risk_categories is None:
            self.risk_categories = [
                "prompt_injection",
                "data_exfiltration", 
                "hate_speech",
                "jailbreak",
                "harmful_content",
                "misinformation",
                "privacy_violation",
                "system_manipulation"
            ]

@dataclass
class LoggingConfig:
    """Logging configurations"""
    level: str = os.getenv("LOG_LEVEL", "INFO")
    structured: bool = os.getenv("ENABLE_STRUCTURED_LOGGING", "true").lower() == "true"
    
@dataclass
class ReportConfig:
    """Report configurations"""
    output_dir: str = os.getenv("REPORT_OUTPUT_DIR", "./reports/")
    generate_visual: bool = os.getenv("GENERATE_VISUAL_REPORTS", "true").lower() == "true"

# Global configuration instance
config = {
    'azure': AzureConfig(),
    'chatbot': ChatbotConfig(),
    'redteam': RedTeamConfig(),
    'logging': LoggingConfig(),
    'report': ReportConfig()
}

def validate_config() -> bool:
    """
    Validates if all required configurations are present
    
    Returns:
        bool: True if all configurations are valid
    """
    required_fields = [
        (config['azure'].client_id, "AZURE_CLIENT_ID"),
        (config['azure'].client_secret, "AZURE_CLIENT_SECRET"),
        (config['azure'].tenant_id, "AZURE_TENANT_ID"),
        (config['azure'].openai_endpoint, "AZURE_OPENAI_ENDPOINT"),
        (config['azure'].openai_api_key, "AZURE_OPENAI_API_KEY")
    ]
    
    missing_fields = []
    for field_value, field_name in required_fields:
        if not field_value:
            missing_fields.append(field_name)
    
    if missing_fields:
        logging.error(f"Missing required fields: {', '.join(missing_fields)}")
        return False
    
    return True

def get_log_level() -> int:
    """Returns the configured logging level"""
    level_map = {
        'DEBUG': logging.DEBUG,
        'INFO': logging.INFO,
        'WARNING': logging.WARNING,
        'ERROR': logging.ERROR,
        'CRITICAL': logging.CRITICAL
    }
    return level_map.get(config['logging'].level.upper(), logging.INFO)