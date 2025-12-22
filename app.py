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
from collections import defaultdict
import threading
import hashlib


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

# 聊天室相关变量
chat_rate_limits = defaultdict(list)  # 存储每个用户的消息发送时间
chat_lock = threading.Lock()  # 线程锁
CHATS_DIR = 'chats'
CONFIG_FILE = os.path.join(CHATS_DIR, 'config.json')
MESSAGES_FILE = os.path.join(CHATS_DIR, 'temps', 'messages.json')
USERS_DIR = os.path.join(CHATS_DIR, 'users')
TEMPS_DIR = os.path.join(CHATS_DIR, 'temps')

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

# 聊天室工具函数
def ensure_directory_exists(directory):
    """确保目录存在，如果不存在则创建"""
    if not os.path.exists(directory):
        try:
            os.makedirs(directory, exist_ok=True)
            print(f'[INFO] 创建目录: {directory}')
        except Exception as e:
            print(f'[ERROR] 创建目录失败 {directory}: {str(e)}')
            return False
    return True

def load_chat_config():
    """加载聊天室配置"""
    # 确保配置目录存在
    ensure_directory_exists(CHATS_DIR)
    ensure_directory_exists(USERS_DIR)
    ensure_directory_exists(TEMPS_DIR)
    
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            config = json.load(f)
            print('[INFO] 成功加载配置文件')
            return config
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f'[WARN] 配置文件不存在或损坏，使用默认配置: {str(e)}')
        # 默认配置
        default_config = {
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
        
        # 保存默认配置
        try:
            with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                json.dump(default_config, f, ensure_ascii=False, indent=4)
            print('[INFO] 已创建并保存默认配置文件')
        except Exception as e:
            print(f'[ERROR] 保存默认配置失败: {str(e)}')
        
        return default_config

def load_messages():
    """加载聊天消息"""
    # 确保目录存在
    ensure_directory_exists(TEMPS_DIR)
    
    try:
        with open(MESSAGES_FILE, 'r', encoding='utf-8') as f:
            messages = json.load(f)
            print(f'[INFO] 成功加载 {len(messages)} 条聊天消息')
            return messages
    except FileNotFoundError:
        print('[WARN] 聊天消息文件不存在，创建空文件')
        # 创建空的消息文件
        try:
            with open(MESSAGES_FILE, 'w', encoding='utf-8') as f:
                json.dump([], f, ensure_ascii=False, indent=2)
            print('[INFO] 已创建空的聊天消息文件')
        except Exception as e:
            print(f'[ERROR] 创建聊天消息文件失败: {str(e)}')
        return []
    except json.JSONDecodeError as e:
        print(f'[ERROR] 聊天消息文件损坏，重置为空: {str(e)}')
        # 文件损坏，备份后重置
        try:
            backup_file = MESSAGES_FILE + '.backup.' + datetime.now().strftime('%Y%m%d_%H%M%S')
            os.rename(MESSAGES_FILE, backup_file)
            print(f'[INFO] 已备份损坏文件为: {backup_file}')
            
            with open(MESSAGES_FILE, 'w', encoding='utf-8') as f:
                json.dump([], f, ensure_ascii=False, indent=2)
            print('[INFO] 已重置聊天消息文件')
        except Exception as e:
            print(f'[ERROR] 备份和重置文件失败: {str(e)}')
        return []

def save_messages(messages):
    """保存聊天消息"""
    # 确保目录存在
    ensure_directory_exists(TEMPS_DIR)
    
    try:
        with open(MESSAGES_FILE, 'w', encoding='utf-8') as f:
            json.dump(messages, f, ensure_ascii=False, indent=2)
        print(f'[INFO] 成功保存 {len(messages)} 条聊天消息')
    except Exception as e:
        print(f'[ERROR] 保存聊天消息失败: {str(e)}')

def check_rate_limit(username, config):
    """检查发送频率限制"""
    now = datetime.now()
    rate_limit = config['rate_limit']['messages_per_minute']
    
    with chat_lock:
        # 清理过期的记录—1分钟前的）
        cutoff_time = now - timedelta(minutes=1)
        chat_rate_limits[username] = [
            timestamp for timestamp in chat_rate_limits[username]
            if timestamp > cutoff_time
        ]
        
        # 检查是否超过限制
        if len(chat_rate_limits[username]) >= rate_limit:
            return False
        
        # 记录新的发送时间
        chat_rate_limits[username].append(now)
        return True

def add_message(username, message):
    """添加新消息"""
    messages = load_messages()
    new_message = {
        'id': str(uuid.uuid4()),
        'username': username,
        'message': message,
        'timestamp': datetime.now().isoformat()
    }
    messages.append(new_message)
    
    # 检查消息数量，如果超过500条则清空前100条
    config = load_chat_config()
    max_messages = config['chat']['message_history_limit']
    cleanup_count = config['chat']['message_cleanup_threshold']
    
    if len(messages) > max_messages:
        messages = messages[cleanup_count:]
    
    save_messages(messages)
    return new_message

# 用户管理相关函数
def hash_password(password):
    """使用SHA256加密密码"""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def load_user(username):
    """加载用户信息"""
    # 确保目录存在
    ensure_directory_exists(USERS_DIR)
    
    user_file = os.path.join(USERS_DIR, f'{username}.json')
    try:
        with open(user_file, 'r', encoding='utf-8') as f:
            user_data = json.load(f)
            print(f'[INFO] 成功加载用户: {username}')
            return user_data
    except FileNotFoundError:
        print(f'[INFO] 用户不存在: {username}')
        return None
    except json.JSONDecodeError as e:
        print(f'[ERROR] 用户数据文件损坏: {username}, 错误: {str(e)}')
        # 备份损坏文件
        try:
            backup_file = user_file + '.backup.' + datetime.now().strftime('%Y%m%d_%H%M%S')
            os.rename(user_file, backup_file)
            print(f'[INFO] 已备份损坏的用户文件: {backup_file}')
        except Exception as e:
            print(f'[ERROR] 备份用户文件失败: {str(e)}')
        return None

def save_user(username, user_data):
    """保存用户信息"""
    # 确保目录存在
    ensure_directory_exists(USERS_DIR)
    
    user_file = os.path.join(USERS_DIR, f'{username}.json')
    try:
        with open(user_file, 'w', encoding='utf-8') as f:
            json.dump(user_data, f, ensure_ascii=False, indent=2)
        print(f'[INFO] 成功保存用户数据: {username}')
    except Exception as e:
        print(f'[ERROR] 保存用户数据失败 {username}: {str(e)}')

def validate_username(username):
    """验证用户名"""
    if not username or len(username) < 2 or len(username) > 20:
        return False, '用户名长度必须在2-20个字符之间'
    if not re.match(r'^[a-zA-Z0-9一-龥_]+$', username):
        return False, '用户名只能包含字母、数字、中文和下划线'
    return True, '用户名合法'

def validate_chat_password(password):
    """验证聊天室密码"""
    config = load_chat_config()
    min_length = config['security']['password_min_length']
    if not password or len(password) < min_length:
        return False, f'密码长度至少{min_length}位'
    return True, '密码合法'

def register_chat_user(username, password):
    """注册聊天室用户"""
    print(f'[INFO] 尝试注册用户: {username}')
    
    # 验证用户名
    valid, msg = validate_username(username)
    if not valid:
        print(f'[WARN] 用户名验证失败: {username} - {msg}')
        return False, msg
    
    # 验证密码
    valid, msg = validate_chat_password(password)
    if not valid:
        print(f'[WARN] 密码验证失败: {username} - {msg}')
        return False, msg
    
    # 检查用户是否已存在
    if load_user(username):
        print(f'[WARN] 用户已存在: {username}')
        return False, '用户名已存在'
    
    # 创建用户
    try:
        user_data = {
            'username': username,
            'password_hash': hash_password(password),
            'created_at': datetime.now().isoformat(),
            'last_login': None
        }
        save_user(username, user_data)
        print(f'[INFO] 成功注册用户: {username}')
        return True, '注册成功'
    except Exception as e:
        print(f'[ERROR] 注册用户失败 {username}: {str(e)}')
        return False, '注册失败，请稍后重试'

def login_chat_user(username, password):
    """聊天室用户登录"""
    print(f'[INFO] 尝试登录用户: {username}')
    
    user_data = load_user(username)
    if not user_data:
        print(f'[WARN] 登录失败，用户不存在: {username}')
        return False, '用户不存在'
    
    password_hash = hash_password(password)
    if user_data['password_hash'] != password_hash:
        print(f'[WARN] 登录失败，密码错误: {username}')
        return False, '密码错误'
    
    # 更新最后登录时间
    try:
        user_data['last_login'] = datetime.now().isoformat()
        save_user(username, user_data)
        print(f'[INFO] 用户登录成功: {username}')
        return True, '登录成功'
    except Exception as e:
        print(f'[ERROR] 更新用户登录时间失败 {username}: {str(e)}')
        # 即使更新失败，也允许登录
        return True, '登录成功'

def cleanup_old_messages():
    """清理过期消息"""
    try:
        config = load_chat_config()
        if not config['chat']['cleanup_schedule']['enabled']:
            return
        
        keep_days = config['chat']['cleanup_schedule']['keep_days']
        cutoff_date = datetime.now() - timedelta(days=keep_days)
        
        messages = load_messages()
        cleaned_messages = []
        
        for msg in messages:
            msg_date = datetime.fromisoformat(msg['timestamp'])
            if msg_date > cutoff_date:
                cleaned_messages.append(msg)
        
        if len(cleaned_messages) != len(messages):
            save_messages(cleaned_messages)
            print(f'清理了 {len(messages) - len(cleaned_messages)} 条过期消息')
    except Exception as e:
        print(f'清理消息失败: {str(e)}')

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

@app.route('/chat')
def chat():
    """聊天室页面 - 需要验证"""
    # 清理过期凭证
    cleanup_expired_credentials()
    
    # 从 cookie 获取 token
    token = request.cookies.get('auth_token')
    
    # 验证用户是否已认证
    if not token or token not in temp_credentials or datetime.now() >= temp_credentials[token]:
        # 未认证用户重定向到登录页面
        return redirect('/login')
    
    # 检查聊天室认证
    chat_token = session.get('chat_token')
    if not chat_token:
        # 需要聊天室认证
        return redirect('/chat/auth')
    
    return render_template('chat.html')

@app.route('/chat/auth')
def chat_auth():
    """聊天室认证页面"""
    # 检查网站认证
    cleanup_expired_credentials()
    token = request.cookies.get('auth_token')
    
    if not token or token not in temp_credentials or datetime.now() >= temp_credentials[token]:
        return redirect('/login')
    
    return render_template('chat_auth.html')

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

# 聊天室API路由
@app.route('/api/chat/register', methods=['POST'])
def register_chat():
    """注册聊天室用户"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'Invalid request'}), 400
        
        username = data.get('username', '').strip()
        password = data.get('password', '')
        
        success, message = register_chat_user(username, password)
        if success:
            return jsonify({'status': 'success', 'message': message})
        else:
            return jsonify({'status': 'error', 'message': message}), 400
            
    except Exception as e:
        return jsonify({'status': 'error', 'message': '注册失败'}), 500

@app.route('/api/chat/login', methods=['POST'])
def login_chat():
    """聊天室用户登录"""
    try:
        # 检查网站认证
        token = request.cookies.get('auth_token')
        if not token or token not in temp_credentials or datetime.now() >= temp_credentials[token]:
            return jsonify({'status': 'error', 'message': '需要先通过网站认证'}), 401
        
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'Invalid request'}), 400
        
        username = data.get('username', '').strip()
        password = data.get('password', '')
        
        success, message = login_chat_user(username, password)
        if success:
            # 生成聊天室token
            chat_token = secrets.token_urlsafe(32)
            session['chat_token'] = chat_token
            session['chat_username'] = username
            
            return jsonify({
                'status': 'success', 
                'message': message,
                'chat_token': chat_token,
                'username': username
            })
        else:
            return jsonify({'status': 'error', 'message': message}), 400
            
    except Exception as e:
        return jsonify({'status': 'error', 'message': '登录失败'}), 500
@app.route('/api/chat/messages', methods=['GET'])
def get_chat_messages():
    """获取聊天消息"""
    try:
        messages = load_messages()
        return jsonify({
            'status': 'success',
            'messages': messages,
            'online_count': len(set(msg['username'] for msg in messages[-20:]))  # 简单的在线人数统计
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': 'Failed to load messages'}), 500

@app.route('/api/chat/send', methods=['POST'])
def send_chat_message():
    """发送聊天消息"""
    try:
        # 检查网站认证
        token = request.cookies.get('auth_token')
        if not token or token not in temp_credentials or datetime.now() >= temp_credentials[token]:
            return jsonify({'status': 'error', 'message': '需要登录后才能发送消息'}), 401
        
        # 检查聊天室认证
        chat_token = session.get('chat_token')
        chat_username = session.get('chat_username')
        if not chat_token or not chat_username:
            return jsonify({'status': 'error', 'message': '需要先登录聊天室'}), 401
        
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'Invalid request'}), 400
        
        message = data.get('message', '').strip()
        
        # 验证输入
        config = load_chat_config()
        if not message or len(message) > config['chat']['max_message_length']:
            return jsonify({'status': 'error', 'message': '消息内容不合法'}), 400
        
        # 检查频率限制
        if not check_rate_limit(chat_username, config):
            return jsonify({
                'status': 'error', 
                'message': f'发送太频繁，每分钟最多发送{config["rate_limit"]["messages_per_minute"]}条消息'
            }), 429
        
        # 添加消息
        new_message = add_message(chat_username, message)
        
        return jsonify({
            'status': 'success',
            'message': new_message
        })
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': '发送消息失败'}), 500

# 启动应用时初始化清理任务
def init_cleanup_scheduler():
    """初始化清理计划任务"""
    import threading
    import time
    
    def cleanup_worker():
        while True:
            try:
                config = load_chat_config()
                if config.get('chat', {}).get('cleanup_schedule', {}).get('enabled', False):
                    interval_hours = config['chat']['cleanup_schedule'].get('interval_hours', 24)
                    cleanup_old_messages()
                    time.sleep(interval_hours * 3600)  # 转换为秒
                else:
                    time.sleep(3600)  # 如果禁用清理，每小时检查一次
            except Exception as e:
                print(f'清理任务错误: {str(e)}')
                time.sleep(3600)
    
    # 在后台线程中运行清理任务
    cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
    cleanup_thread.start()

if __name__ == '__main__':  # 当脚本直接运行时执行以下代码
    # 初始化清理计划任务
    init_cleanup_scheduler()
    app.run(host='0.0.0.0', port=5070, threaded=True)  # 启动Flask应用