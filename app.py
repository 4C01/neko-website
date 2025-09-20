from flask import Flask, request, redirect, render_template, send_from_directory, jsonify, session  # 导入Flask框架、request对象和redirect函数，用于处理HTTP请求和重定向
import os
import json
import bcrypt
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, timedelta
import uuid
import secrets
import re
from functools import wraps


# 获取真实IP地址
# 是否信任代理头，仅在使用可信反向代理时设置为True
TRUST_PROXY_HEADERS = False

def get_real_ip():
    # 获取真实IP地址，考虑代理情况
    if TRUST_PROXY_HEADERS:
        if request.headers.get('X-Forwarded-For'):
            ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
        elif request.headers.get('X-Real-IP'):
            ip = request.headers.get('X-Real-IP')
        else:
            ip = request.remote_addr
    else:
        ip = request.remote_addr
    return ip

# 配置日志记录
def setup_logging():
    # 创建日志目录
    if not os.path.exists('logs'):
        os.makedirs('logs')
    
    # 配置访问日志
    access_logger = logging.getLogger('access')
    access_logger.setLevel(logging.INFO)
    
    # 创建文件处理器
    access_handler = RotatingFileHandler('logs/access.log', maxBytes=10485760, backupCount=10)
    access_handler.setLevel(logging.INFO)
    
    # 创建日志格式
    formatter = logging.Formatter('%(asctime)s - %(message)s')
    access_handler.setFormatter(formatter)
    
    # 添加处理器到日志记录器
    access_logger.addHandler(access_handler)
    access_logger.propagate = False  # 防止日志传播到根记录器
    
    return access_logger

# 配置密码操作日志记录
def setup_password_logging():
    # 配置密码操作日志
    pwd_logger = logging.getLogger('password')
    pwd_logger.setLevel(logging.INFO)
    
    # 创建文件处理器
    pwd_handler = RotatingFileHandler('logs/password.log', maxBytes=10485760, backupCount=10)
    pwd_handler.setLevel(logging.INFO)
    
    # 创建日志格式
    formatter = logging.Formatter('%(asctime)s - %(message)s')
    pwd_handler.setFormatter(formatter)
    
    # 添加处理器到日志记录器
    pwd_logger.addHandler(pwd_handler)
    pwd_logger.propagate = False  # 防止日志传播到根记录器
    
    return pwd_logger

# 记录密码操作
def log_password_operation(operation, ip):
    pwd_logger = setup_password_logging()
    pwd_logger.info(f'{ip} - "{operation}"')

# 存储IP错误次数和封禁状态
# 结构: {ip: {'count': 错误次数, 'last_attempt': 最后尝试时间, 'blocked': 是否被封禁}}
ip_attempts = {}
blocked_ips = set()  # 被永久封禁的IP
temp_credentials = {} # 存储临时凭证

# 密码强度验证
def validate_password_strength(password):
    """验证密码强度"""
    if len(password) < 6:
        return False, "密码长度至少6位"
    # 可选：如果需要更强的密码策略，可以启用以下验证
    # if not re.search(r'[A-Z]', password):
    #     return False, "密码必须包含大写字母"
    # if not re.search(r'[a-z]', password):
    #     return False, "密码必须包含小写字母"
    # if not re.search(r'\d', password):
    #     return False, "密码必须包含数字"
    # if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
    #     return False, "密码必须包含特殊字符"
    return True, "密码强度合格"

# 清理过期的临时凭证
def cleanup_expired_credentials():
    """清理过期的临时凭证"""
    current_time = datetime.now()
    expired_tokens = [token for token, expiration in temp_credentials.items() if current_time >= expiration]
    for token in expired_tokens:
        del temp_credentials[token]

# CSRF保护装饰器
def csrf_protect(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == "POST":
            token = session.get('_csrf_token')
            if not token or token != request.form.get('_csrf_token'):
                return jsonify({'error': 'CSRF token missing or invalid'}), 403
        return f(*args, **kwargs)
    return decorated_function

# 生成CSRF token
def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(16)
    return session['_csrf_token']

# 将CSRF token添加到模板上下文
# 注意：这行代码需要在app创建后执行

# 检查IP是否被封禁
def is_ip_blocked(ip):
    # 检查是否被永久封禁
    if ip in blocked_ips:
        return True
    
    # 检查是否有临时封禁记录
    if ip in ip_attempts:
        attempt_info = ip_attempts[ip]
        
        # 如果错误次数超过500次，永久封禁
        if attempt_info['count'] >= 500:
            blocked_ips.add(ip)
            return True
        
        # 如果错误次数超过3次，检查是否在冷却期
        if attempt_info['count'] >= 3:
            # 检查是否在60秒冷却期内
            if datetime.now() - attempt_info['last_attempt'] < timedelta(seconds=60):
                return True
    
    return False

# 记录密码错误
def record_failed_attempt(ip):
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
        
        # 如果错误次数达到500次，永久封禁
        if attempt_info['count'] >= 500:
            blocked_ips.add(ip)
            attempt_info['blocked'] = True

# 重置IP尝试次数（可选功能，用于管理员手动解除限制）
def reset_ip_attempts(ip):
    if ip in ip_attempts:
        del ip_attempts[ip]
    if ip in blocked_ips:
        blocked_ips.remove(ip)

# 初始化日志记录器
access_logger = setup_logging()

app = Flask(__name__, static_folder='static', template_folder='templates')  # 创建Flask应用实例

# 设置安全密钥
app.secret_key = secrets.token_hex(32)

# 添加安全头
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
    return response

# 将CSRF token添加到模板上下文
app.jinja_env.globals['csrf_token'] = generate_csrf_token

# 添加请求前后处理器来记录日志
@app.before_request
def log_request_info():
    # 记录请求信息
    ip = get_real_ip()
    method = request.method
    url = request.url
    user_agent = request.headers.get('User-Agent', '')
    
    # 记录访问日志
    access_logger.info(f'{ip} - "{method} {url}" - "{user_agent}"')

# 配置文件路径
CONFIG_DIR = 'config'
PWD_FILE = os.path.join(CONFIG_DIR, 'pwd.json')

# 确保配置目录存在
os.makedirs(CONFIG_DIR, exist_ok=True)

# 如果密码文件不存在，表示是首次登录
FIRST_LOGIN = not os.path.exists(PWD_FILE)

@app.route('/')
def index():
    # 检查是否有环境异常提示
    blocked = request.args.get('blocked', False)
    return render_template('index.html', blocked=blocked)

@app.route('/is_first_login')
def is_first_login():
    global FIRST_LOGIN
    return {'is_first_login': FIRST_LOGIN}

@app.route('/login', methods=['GET', 'POST'])  # 定义/login路由，接受GET和POST请求
def login():  # 定义处理登录请求的函数
    global FIRST_LOGIN
    
    # 获取用户IP
    ip = get_real_ip()
    
    # 检查IP是否被封禁
    if is_ip_blocked(ip):
        log_password_operation('Login attempt from blocked IP', ip)
        # 修改：IP被封禁时返回特定JSON响应而不是重定向
        return jsonify({'error': 'blocked', 'message': 'IP is blocked'}), 403
    
    if request.method == 'GET':
        # 渲染登录页面
        return render_template('login.html')
    elif request.method == 'POST':
        # 处理登录表单提交
        pwd = request.form.get('pwd')  # 从表单数据中获取pwd字段的值
        
        if FIRST_LOGIN:
            # 首次登录，设置密码
            # 验证密码强度
            is_valid, message = validate_password_strength(pwd)
            if not is_valid:
                log_password_operation(f'Weak password rejected: {message}', ip)
                return jsonify({'status': 'weak_password', 'message': message}), 400
            
            hashed = bcrypt.hashpw(pwd.encode('utf-8'), bcrypt.gensalt())
            with open(PWD_FILE, 'w', encoding='utf-8') as f:
                json.dump({'password': hashed.decode('utf-8')}, f)
            FIRST_LOGIN = False
            # 记录密码设置操作，不记录明文密码
            log_password_operation('Password set', ip)
            
            # 清理过期凭证
            cleanup_expired_credentials()
            
            # 生成临时凭证
            token = secrets.token_urlsafe(32)
            expiration = datetime.now() + timedelta(minutes=30)
            temp_credentials[token] = expiration
            
            return jsonify({'status': '200ok', 'token': token}) # 设置成功
        else:
            # 验证密码
            try:
                with open(PWD_FILE, 'r', encoding='utf-8') as f:
                    stored_data = json.load(f)
                stored_hash = stored_data['password'].encode('utf-8')
                
                if bcrypt.checkpw(pwd.encode('utf-8'), stored_hash):
                    # 记录登录成功操作
                    log_password_operation('Login successful', ip)
                    # 重置错误计数
                    if ip in ip_attempts:
                        del ip_attempts[ip]
                    
                    # 清理过期凭证
                    cleanup_expired_credentials()
                    
                    # 生成临时凭证
                    token = secrets.token_urlsafe(32)
                    expiration = datetime.now() + timedelta(minutes=30)
                    temp_credentials[token] = expiration

                    return jsonify({'status': '200ok', 'token': token}) # 密码正确
                else:
                    # 记录登录失败操作
                    log_password_operation('Login failed', ip)
                    # 记录失败尝试
                    record_failed_attempt(ip)
                    return jsonify({'status': '401error'}), 401  # 密码错误
            except (FileNotFoundError, json.JSONDecodeError, KeyError) as e:
                log_password_operation(f'Login error: {str(e)}', ip)
                return jsonify({'status': '500error', 'message': 'Server error'}), 500

@app.route('/tpy')
def tpy():
    return render_template('tpy.html')

@app.route('/check_auth')
def check_auth():
    """检查用户是否已认证（通过cookie）"""
    # 清理过期凭证
    cleanup_expired_credentials()
    
    # 从 cookie 获取 token
    token = request.cookies.get('auth_token')
    
    if token and token in temp_credentials and datetime.now() < temp_credentials[token]:
        return jsonify({'authenticated': True, 'message': '已认证'})
    else:
        return jsonify({'authenticated': False, 'message': '未认证或认证已过期'})

@app.route('/validate_token', methods=['POST'])
def validate_token():
    # 清理过期凭证
    cleanup_expired_credentials()
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({'status': 'failure', 'message': 'Invalid request'}), 400
            
        token = data.get('token')
        if not token:
            return jsonify({'status': 'failure', 'message': 'Token required'}), 400

        if token in temp_credentials and datetime.now() < temp_credentials[token]:
            # 验证成功，设置cookie
            response = jsonify({'status': 'success'})
            # 设置7天有效期的cookie
            response.set_cookie('auth_token', token, 
                              max_age=7*24*60*60,  # 7天
                              httponly=True,       # 仅HTTP访问，防止XSS
                              secure=False,        # 在HTTPS下设为True
                              samesite='Strict')   # CSRF保护
            return response
        else:
            # 记录无效token尝试，但不泄露敏感信息
            ip = get_real_ip()
            log_password_operation('Invalid token validation attempt', ip)
            return jsonify({'status': 'failure', 'message': 'Invalid or expired token'}), 401
    except Exception as e:
        ip = get_real_ip()
        log_password_operation(f'Token validation error: {str(e)}', ip)
        return jsonify({'status': 'failure', 'message': 'Server error'}), 500

if __name__ == '__main__':  # 当脚本直接运行时执行以下代码
    app.run(host='0.0.0.0', port=5000, threaded=True)  # 启动Flask应用