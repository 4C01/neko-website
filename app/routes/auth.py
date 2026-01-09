from flask import render_template, request, jsonify, redirect, url_for
from . import auth_bp
from ..services.auth_service import AuthService

@auth_bp.route('/is_first_login')
def is_first_login():
    """检查是否是首次登录"""
    return {'is_first_login': AuthService.is_first_login()}

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """登录路由"""
    if request.method == 'GET':
        # 渲染登录页面
        return render_template('login.html')
    elif request.method == 'POST':
        # 处理登录表单提交
        pwd = request.form.get('pwd')
        
        if AuthService.is_first_login():
            # 首次登录，设置密码
            success, message = AuthService.setup_password(pwd)
            if not success:
                return jsonify({'status': 'weak_password', 'message': message}), 400
            
            # 生成临时凭证
            success, token, status_code = AuthService.login(pwd)
            if success:
                return jsonify({'status': '200ok', 'token': token})
            else:
                return jsonify({'status': '500error', 'message': '服务器错误'}), 500
        else:
            # 普通登录
            success, result, status_code = AuthService.login(pwd)
            if success:
                return jsonify({'status': '200ok', 'token': result})
            else:
                return jsonify({'status': '401error' if status_code == 401 else '500error', 'message': result}), status_code

@auth_bp.route('/check_auth')
def check_auth():
    """检查用户是否已认证"""
    success, message = AuthService.is_authenticated()
    return jsonify({'authenticated': success, 'message': message})

@auth_bp.route('/validate_token', methods=['POST'])
def validate_token():
    """验证令牌"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'status': 'failure', 'message': 'Invalid request'}), 400
            
        token = data.get('token')
        if not token:
            return jsonify({'status': 'failure', 'message': 'Token required'}), 400

        success, message = AuthService.validate_token(token)
        if success:
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
            return jsonify({'status': 'failure', 'message': message}), 401
    except Exception as e:
        print(f"Error in validate_token: {str(e)}")
        return jsonify({'status': 'failure', 'message': 'Server error'}), 500
