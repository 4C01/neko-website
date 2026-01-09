from flask import render_template, request, jsonify, redirect, url_for, session
from . import chat_bp
from ..services.auth_service import AuthService
from ..services.chat_service import ChatService

@chat_bp.route('/chat')
def chat():
    """聊天室页面"""
    # 清理过期凭证
    AuthService.cleanup_expired_credentials()
    
    # 从 cookie 获取 token
    token = request.cookies.get('auth_token')
    
    # 验证用户是否已认证
    if not token or not AuthService.validate_token(token)[0]:
        # 未认证用户重定向到登录页面
        return redirect('/login')
    
    # 检查聊天室认证
    chat_token = session.get('chat_token')
    if not chat_token:
        # 需要聊天室认证
        return redirect('/chat/auth')
    
    return render_template('chat.html')

@chat_bp.route('/chat/auth')
def chat_auth():
    """聊天室认证页面"""
    # 检查网站认证
    AuthService.cleanup_expired_credentials()
    token = request.cookies.get('auth_token')
    
    if not token or not AuthService.validate_token(token)[0]:
        return redirect('/login')
    
    return render_template('chat_auth.html')

@chat_bp.route('/api/chat/register', methods=['POST'])
def register_chat():
    """注册聊天室用户"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'Invalid request'}), 400
        
        username = data.get('username', '').strip()
        password = data.get('password', '')
        
        success, message = ChatService.register_user(username, password)
        if success:
            return jsonify({'status': 'success', 'message': message})
        else:
            return jsonify({'status': 'error', 'message': message}), 400
            
    except Exception as e:
        return jsonify({'status': 'error', 'message': '注册失败'}), 500

@chat_bp.route('/api/chat/login', methods=['POST'])
def login_chat():
    """聊天室用户登录"""
    try:
        # 检查网站认证
        token = request.cookies.get('auth_token')
        if not token or not AuthService.validate_token(token)[0]:
            return jsonify({'status': 'error', 'message': '需要先通过网站认证'}), 401
        
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'Invalid request'}), 400
        
        username = data.get('username', '').strip()
        password = data.get('password', '')
        
        success, message = ChatService.login_user(username, password)
        if success:
            # 生成聊天室token
            chat_token = AuthService.generate_chat_token(username)
            
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

@chat_bp.route('/api/chat/messages', methods=['GET'])
def get_chat_messages():
    """获取聊天消息"""
    try:
        messages, online_count = ChatService.get_messages()
        return jsonify({
            'status': 'success',
            'messages': messages,
            'online_count': online_count
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': 'Failed to load messages'}), 500

@chat_bp.route('/api/chat/send', methods=['POST'])
def send_chat_message():
    """发送聊天消息"""
    try:
        # 检查网站认证
        token = request.cookies.get('auth_token')
        if not token or not AuthService.validate_token(token)[0]:
            return jsonify({'status': 'error', 'message': '需要登录后才能发送消息'}), 401
        
        # 检查聊天室认证
        is_chat_auth, username = AuthService.is_chat_authenticated()
        if not is_chat_auth or not username:
            return jsonify({'status': 'error', 'message': '需要先登录聊天室'}), 401
        
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'Invalid request'}), 400
        
        message = data.get('message', '').strip()
        
        # 发送消息
        success, result = ChatService.send_message(username, message)
        if success:
            return jsonify({
                'status': 'success',
                'message': result
            })
        else:
            return jsonify({'status': 'error', 'message': result}), 429
            
    except Exception as e:
        return jsonify({'status': 'error', 'message': '发送消息失败'}), 500

@chat_bp.route('/api/chat/clear', methods=['POST'])
def clear_chat_messages():
    """清除聊天记录"""
    try:
        # 检查网站认证
        token = request.cookies.get('auth_token')
        if not token or not AuthService.validate_token(token)[0]:
            return jsonify({'status': 'error', 'message': '需要登录后才能清除记录'}), 401
        
        # 检查聊天室认证
        is_chat_auth, username = AuthService.is_chat_authenticated()
        if not is_chat_auth or not username:
            return jsonify({'status': 'error', 'message': '需要先登录聊天室'}), 401
        
        # 清除聊天记录
        from ..services.chat_service import ChatService
        success = ChatService.clear_messages()
        
        if success:
            return jsonify({'status': 'success', 'message': '聊天记录已清除'})
        else:
            return jsonify({'status': 'error', 'message': '清除聊天记录失败'}), 500
            
    except Exception as e:
        return jsonify({'status': 'error', 'message': '清除聊天记录失败'}), 500
