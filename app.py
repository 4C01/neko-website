from flask import Flask, request, redirect, render_template, send_from_directory  # 导入Flask框架、request对象和redirect函数，用于处理HTTP请求和重定向
import os
import json
import bcrypt

app = Flask(__name__, static_folder='static', template_folder='templates')  # 创建Flask应用实例

# 配置文件路径
CONFIG_DIR = 'config'
PWD_FILE = os.path.join(CONFIG_DIR, 'pwd.json')

# 确保配置目录存在
os.makedirs(CONFIG_DIR, exist_ok=True)

# 如果密码文件不存在，表示是首次登录
FIRST_LOGIN = not os.path.exists(PWD_FILE)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/is_first_login')
def is_first_login():
    global FIRST_LOGIN
    return {'is_first_login': FIRST_LOGIN}

@app.route('/login', methods=['GET', 'POST'])  # 定义/login路由，接受GET和POST请求
def login():  # 定义处理登录请求的函数
    global FIRST_LOGIN
    
    if request.method == 'GET':
        # 渲染登录页面
        return render_template('login.html')
    elif request.method == 'POST':
        # 处理登录表单提交
        pwd = request.form.get('pwd')  # 从表单数据中获取pwd字段的值
        
        if FIRST_LOGIN:
            # 首次登录，设置密码
            hashed = bcrypt.hashpw(pwd.encode('utf-8'), bcrypt.gensalt())
            with open(PWD_FILE, 'w') as f:
                json.dump({'password': hashed.decode('utf-8')}, f)
            FIRST_LOGIN = False
            return "200ok"  # 设置成功
        else:
            # 验证密码
            with open(PWD_FILE, 'r') as f:
                stored_data = json.load(f)
            stored_hash = stored_data['password'].encode('utf-8')
            
            if bcrypt.checkpw(pwd.encode('utf-8'), stored_hash):
                return "200ok"  # 密码正确
            else:
                return "401error", 401  # 密码错误

if __name__ == '__main__':  # 当脚本直接运行时执行以下代码
    app.run(host='0.0.0.0', port=5000, threaded=True)  # 启动Flask应用