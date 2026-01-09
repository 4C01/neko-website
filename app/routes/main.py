from flask import render_template, redirect, url_for, request
from . import main_bp

@main_bp.route('/')
def index():
    """主页"""
    # 检查是否有环境异常提示
    blocked = request.args.get('blocked', False)
    return render_template('index.html', blocked=blocked)

@main_bp.route('/tpy')
def tpy():
    """tpy页面"""
    return render_template('tpy.html')
