import os
import secrets
import json
from datetime import datetime, timedelta
from flask import request, session
from ..config import Config
from ..utils.security import (
    hash_password, verify_password, validate_password_strength,
    is_ip_blocked, record_failed_attempt, reset_ip_attempts,
    log_password_operation, get_real_ip
)
from ..utils.helpers import load_json_file, save_json_file, cleanup_expired_items

# 存储临时凭证
temp_credentials = {}

class AuthService:
    """认证服务"""
    
    @staticmethod
    def is_first_login():
        """检查是否是首次登录"""
        return not os.path.exists(Config.PWD_FILE)
    
    @staticmethod
    def setup_password(password):
        """设置初始密码"""
        # 验证密码强度
        is_valid, message = validate_password_strength(password)
        if not is_valid:
            return False, message
        
        # 生成密码哈希
        hashed = hash_password(password)
        
        # 保存密码
        if save_json_file(Config.PWD_FILE, {'password': hashed}):
            return True, '密码设置成功'
        else:
            return False, '密码保存失败'
    
    @staticmethod
    def login(password):
        """用户登录"""
        ip = get_real_ip()
        
        # 检查IP是否被封禁
        if is_ip_blocked(ip):
            log_password_operation('Login attempt from blocked IP', ip)
            return False, 'IP is blocked', 403
        
        try:
            # 加载存储的密码
            stored_data = load_json_file(Config.PWD_FILE)
            stored_hash = stored_data['password']
            
            # 验证密码
            if verify_password(password, stored_hash):
                # 记录登录成功
                log_password_operation('Login successful', ip)
                
                # 重置错误计数
                reset_ip_attempts(ip)
                
                # 生成临时凭证
                token = secrets.token_urlsafe(32)
                expiration = datetime.now() + timedelta(minutes=30)
                temp_credentials[token] = expiration
                
                return True, token, 200
            else:
                # 记录登录失败
                log_password_operation('Login failed', ip)
                record_failed_attempt(ip)
                return False, '密码错误', 401
                
        except (FileNotFoundError, json.JSONDecodeError, KeyError) as e:
            log_password_operation(f'Login error: {str(e)}', ip)
            return False, '服务器错误', 500
    
    @staticmethod
    def validate_token(token):
        """验证令牌"""
        # 清理过期凭证
        cleanup_expired_items(temp_credentials, current_time=datetime.now())
        
        if token and token in temp_credentials:
            return True, '令牌有效'
        else:
            return False, '令牌无效或已过期'
    
    @staticmethod
    def get_auth_token_from_cookie():
        """从cookie获取认证令牌"""
        return request.cookies.get('auth_token')
    
    @staticmethod
    def is_authenticated():
        """检查用户是否已认证"""
        # 清理过期凭证
        cleanup_expired_items(temp_credentials, current_time=datetime.now())
        
        # 从cookie获取令牌
        token = AuthService.get_auth_token_from_cookie()
        
        # 验证令牌
        return AuthService.validate_token(token)
    
    @staticmethod
    def cleanup_expired_credentials():
        """清理过期凭证"""
        cleanup_expired_items(temp_credentials, current_time=datetime.now())
    
    @staticmethod
    def generate_chat_token(username):
        """生成聊天室令牌"""
        chat_token = secrets.token_urlsafe(32)
        session['chat_token'] = chat_token
        session['chat_username'] = username
        return chat_token
    
    @staticmethod
    def is_chat_authenticated():
        """检查聊天室认证"""
        chat_token = session.get('chat_token')
        chat_username = session.get('chat_username')
        return bool(chat_token and chat_username), chat_username
