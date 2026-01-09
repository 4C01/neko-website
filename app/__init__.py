from flask import Flask, request
from .config import config_by_name
from .routes import main_bp, auth_bp, chat_bp
from .utils.security import log_request_info, add_security_headers, generate_csrf_token
from .services.chat_service import ChatService

# 初始化Flask应用
def create_app(config_name='default'):
    """创建Flask应用实例"""
    app = Flask(__name__, static_folder='../static', template_folder='../templates')
    
    # 加载配置
    app.config.from_object(config_by_name[config_name])
    
    # 设置安全密钥
    app.secret_key = app.config['SECRET_KEY']
    
    # 注册蓝图
    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(chat_bp)
    
    # 将CSRF token添加到模板上下文
    app.jinja_env.globals['csrf_token'] = generate_csrf_token
    
    # 添加请求前后处理器来记录日志
    @app.before_request
    def before_request():
        log_request_info()
    
    # 添加安全头
    @app.after_request
    def after_request(response):
        return add_security_headers(response)
    
    return app

# 初始化应用
app = create_app()

# 启动清理计划任务
ChatService.init_cleanup_scheduler()
