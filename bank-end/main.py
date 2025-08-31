from flask import Flask, request, redirect  # 导入Flask框架、request对象和redirect函数，用于处理HTTP请求和重定向

app = Flask(__name__)  # 创建Flask应用实例

# 正确的密码
CORRECT_PASSWORD = "admin0721"  # 设置用于验证的正确密码

@app.route('/login', methods=['GET'])  # 定义/login路由，只接受GET请求
def login():  # 定义处理登录请求的函数
    pwd = request.args.get('pwd')  # 从请求参数中获取pwd字段的值
    
    if pwd == CORRECT_PASSWORD:  # 检查提供的密码是否与正确密码匹配
        return "200ok" # 如果代码正确，返回200ok
    else:
        return "401 Unauthorized", 401  # 如果密码错误，返回401错误代码

if __name__ == '__main__':  # 当脚本直接运行时执行以下代码
    import time  # 导入time模块，用于控制循环间隔
    from threading import Thread  # 导入Thread类，用于在后台运行Flask应用
    
    def run_app():
        app.run(host='0.0.0.0', port=5000, threaded=True)  # 在单独的线程中启动Flask应用
    
    thread = Thread(target=run_app)  # 创建线程
    thread.start()  # 启动线程
    
    while True:  # 持续监测循环
        time.sleep(0.1)  # 每0.1秒循环一次