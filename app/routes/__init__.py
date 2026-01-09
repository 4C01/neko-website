from flask import Blueprint

# 创建路由蓝图
main_bp = Blueprint('main', __name__)
auth_bp = Blueprint('auth', __name__)
chat_bp = Blueprint('chat', __name__)

# 导入路由处理函数
from . import main
from . import auth
from . import chat
