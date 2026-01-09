import bcrypt
import secrets
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, timedelta
from functools import wraps
from flask import request, session, jsonify
import os
from ..config import Config

# 存储IP错误次数和封禁状态
ip_attempts = {}
blocked_ips = set()  # 被永久封禁的IP

def setup_logging(name, file_name):
    """配置日志记录"""
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    
    # 创建文件处理器
    log_file = os.path.join(Config.LOGS_DIR, file_name)
    handler = RotatingFileHandler(log_file, maxBytes=10485760, backupCount=10)
    handler.setLevel(logging.INFO)
    
    # 创建日志格式
    formatter = logging.Formatter('%(asctime)s - %(message)s')
    handler.setFormatter(formatter)
    
    # 添加处理器到日志记录器
    logger.addHandler(handler)
    logger.propagate = False  # 防止日志传播到根记录器
    
    return logger

# 初始化日志记录器
access_logger = setup_logging('access', 'access.log')
pwd_logger = setup_logging('password', 'password.log')

def get_real_ip():
    """获取真实IP地址，考虑代理情况"""
    if Config.TRUST_PROXY_HEADERS:
        if request.headers.get('X-Forwarded-For'):
            ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
        elif request.headers.get('X-Real-IP'):
            ip = request.headers.get('X-Real-IP')
        else:
            ip = request.remote_addr
    else:
        ip = request.remote_addr
    return ip

def log_password_operation(operation, ip):
    """记录密码操作"""
    pwd_logger.info(f'{ip} - "{operation}"')

def hash_password(password):
    """使用bcrypt加密密码"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password, hashed_password):
    """验证密码"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

def validate_password_strength(password):
    """验证密码强度"""
    if len(password) < Config.SECURITY['PASSWORD_MIN_LENGTH']:
        return False, f"密码长度至少{Config.SECURITY['PASSWORD_MIN_LENGTH']}位"
    return True, "密码强度合格"

def generate_csrf_token():
    """生成CSRF token"""
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(16)
    return session['_csrf_token']

def csrf_protect(f):
    """CSRF保护装饰器"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == "POST":
            token = session.get('_csrf_token')
            if not token or token != request.form.get('_csrf_token'):
                return jsonify({'error': 'CSRF token missing or invalid'}), 403
        return f(*args, **kwargs)
    return decorated_function

def is_ip_blocked(ip):
    """检查IP是否被封禁"""
    # 检查是否被永久封禁
    if ip in blocked_ips:
        return True
    
    # 检查是否有临时封禁记录
    if ip in ip_attempts:
        attempt_info = ip_attempts[ip]
        
        # 如果错误次数超过永久封禁阈值，永久封禁
        if attempt_info['count'] >= Config.SECURITY['PERMANENT_LOCKOUT_ATTEMPTS']:
            blocked_ips.add(ip)
            return True
        
        # 如果错误次数超过临时封禁阈值，检查是否在冷却期
        if attempt_info['count'] >= Config.SECURITY['MAX_LOGIN_ATTEMPTS']:
            # 检查是否在冷却期内
            if datetime.now() - attempt_info['last_attempt'] < Config.SECURITY['LOCKOUT_DURATION']:
                return True
    
    return False

def record_failed_attempt(ip):
    """记录失败尝试"""
    now = datetime.now()
    
    if ip not in ip_attempts:
        ip_attempts[ip] = {
            'count': 1,
            'last_attempt': now,
            'blocked': False
        }
    else:
        attempt_info = ip_attempts[ip]
        attempt_info['count'] += 1
        attempt_info['last_attempt'] = now
        
        # 如果错误次数达到永久封禁阈值，永久封禁
        if attempt_info['count'] >= Config.SECURITY['PERMANENT_LOCKOUT_ATTEMPTS']:
            blocked_ips.add(ip)
            attempt_info['blocked'] = True

def reset_ip_attempts(ip):
    """重置IP尝试次数"""
    if ip in ip_attempts:
        del ip_attempts[ip]
    if ip in blocked_ips:
        blocked_ips.remove(ip)

def log_request_info():
    """记录请求信息"""
    ip = get_real_ip()
    method = request.method
    url = request.url
    user_agent = request.headers.get('User-Agent', '')
    
    # 记录访问日志
    access_logger.info(f'{ip} - "{method} {url}" - "{user_agent}"')

def add_security_headers(response):
    """添加安全头"""
    for header, value in Config.SECURITY_HEADERS.items():
        response.headers[header] = value
    return response
