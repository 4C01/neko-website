from flask import Flask, request, redirect, render_template, send_from_directory  # 导入Flask框架、request对象和redirect函数，用于处理HTTP请求和重定向
import os

app = Flask(__name__, static_folder='static', template_folder='templates')  # 创建Flask应用实例

# 正确的密码
CORRECT_PASSWORD = "admin0721"  # 设置用于验证的正确密码

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])  # 定义/login路由，接受GET和POST请求
def login():  # 定义处理登录请求的函数
    if request.method == 'GET':
        # 渲染登录页面
        return render_template('login.html')
    elif request.method == 'POST':
        # 处理登录表单提交
        pwd = request.form.get('pwd')  # 从表单数据中获取pwd字段的值
        
        if pwd == CORRECT_PASSWORD:  # 检查提供的密码是否与正确密码匹配
            return "200ok" # 如果代码正确，返回200ok
        else:
            return "401error", 401  # 如果密码错误，返回401错误代码

if __name__ == '__main__':  # 当脚本直接运行时执行以下代码
    app.run(host='0.0.0.0', port=5000, threaded=True)  # 启动Flask应用