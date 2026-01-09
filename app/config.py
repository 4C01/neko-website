import os
from datetime import timedelta

class Config:
    """基础配置类"""
    # 应用设置
    SECRET_KEY = os.environ.get('SECRET_KEY') or os.urandom(32)
    DEBUG = False
    TESTING = False
    
    # 信任代理头设置
    TRUST_PROXY_HEADERS = False
    
    # 路径设置
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, '..'))
    
    # 配置文件路径
    CONFIG_DIR = os.path.join(PROJECT_ROOT, 'config')
    PWD_FILE = os.path.join(CONFIG_DIR, 'pwd.json')
    
    # 聊天室相关路径
    CHATS_DIR = os.path.join(PROJECT_ROOT, 'chats')
    USERS_DIR = os.path.join(CHATS_DIR, 'users')
    TEMPS_DIR = os.path.join(CHATS_DIR, 'temps')
    CONFIG_FILE = os.path.join(CHATS_DIR, 'config.json')
    MESSAGES_FILE = os.path.join(TEMPS_DIR, 'messages.json')
    
    # 日志设置
    LOGS_DIR = os.path.join(PROJECT_ROOT, 'logs')
    
    # 安全设置
    SECURITY = {
        'PASSWORD_MIN_LENGTH': 6,
        'MAX_LOGIN_ATTEMPTS': 3,
        'LOCKOUT_DURATION': timedelta(seconds=60),
        'PERMANENT_LOCKOUT_ATTEMPTS': 500,
        'SESSION_COOKIE_HTTPONLY': True,
        'SESSION_COOKIE_SECURE': False,  # 在HTTPS下设为True
        'SESSION_COOKIE_SAMESITE': 'Strict',
    }
    
    # 聊天室默认配置
    DEFAULT_CHAT_CONFIG = {
        "rate_limit": {
            "messages_per_minute": 30,
            "cleanup_interval": 300
        },
        "chat": {
            "max_message_length": 500,
            "max_username_length": 20,
            "message_history_limit": 500,
            "message_cleanup_threshold": 100,
            "cleanup_schedule": {
                "enabled": True,
                "interval_hours": 24,
                "keep_days": 7
            }
        },
        "security": {
            "require_auth": True,
            "require_registration": True,
            "filter_content": True,
            "banned_words": ["spam", "advertisement"],
            "password_min_length": 6
        },
        "paths": {
            "temp_messages": "chats/temps",
            "users": "chats/users",
            "config": "chats/config.json"
        }
    }
    
    # 安全头设置
    SECURITY_HEADERS = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
    }

class DevelopmentConfig(Config):
    """开发环境配置"""
    DEBUG = True

class ProductionConfig(Config):
    """生产环境配置"""
    DEBUG = False
    
    def __init__(self):
        super().__init__()
        self.SECURITY['SESSION_COOKIE_SECURE'] = True  # 生产环境启用HTTPS

# 根据环境变量选择配置
config_by_name = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}

# 确保配置目录存在
os.makedirs(Config.CONFIG_DIR, exist_ok=True)
os.makedirs(Config.LOGS_DIR, exist_ok=True)
os.makedirs(Config.CHATS_DIR, exist_ok=True)
os.makedirs(Config.USERS_DIR, exist_ok=True)
os.makedirs(Config.TEMPS_DIR, exist_ok=True)
