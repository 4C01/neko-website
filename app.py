from app import app
import threading
import sys
import time
from app.services.chat_service import ChatService

# 处理终端输入的函数
def handle_terminal_input():
    """处理终端输入，支持/clear命令清除聊天记录"""
    print("\n终端命令提示：")
    print("  /clear - 清除所有聊天记录")
    print("  /help  - 显示帮助信息")
    print("按Ctrl+C退出应用\n")
    
    # 检测操作系统
    is_windows = sys.platform.startswith('win')
    
    # Windows系统使用msvcrt模块
    if is_windows:
        import msvcrt
        input_buffer = ""
    
    while True:
        try:
            # 使用input()会阻塞主线程，所以我们需要使用非阻塞方式
            time.sleep(0.1)
            
            if is_windows:
                # Windows系统使用msvcrt
                while msvcrt.kbhit():
                    char = msvcrt.getch().decode('utf-8')
                    if char == '\r':  # Enter键
                        command = input_buffer.strip()
                        input_buffer = ""
                        print()  # 换行
                        
                        if command == '/clear':
                            print("正在清除聊天记录...")
                            success = ChatService.clear_messages()
                            if success:
                                print("聊天记录已成功清除！\n")
                            else:
                                print("清除聊天记录失败！\n")
                        elif command == '/help':
                            print("\n终端命令列表：")
                            print("  /clear - 清除所有聊天记录")
                            print("  /help  - 显示帮助信息\n")
                        elif command:
                            print(f"\n未知命令: {command}")
                            print("输入/help查看可用命令\n")
                    elif char == '\x08':  # 退格键
                        if input_buffer:
                            input_buffer = input_buffer[:-1]
                            # 删除终端上的字符
                            sys.stdout.write('\b \b')
                            sys.stdout.flush()
                    else:
                        input_buffer += char
                        sys.stdout.write(char)
                        sys.stdout.flush()
            else:
                # 非Windows系统使用select
                import select
                if sys.stdin in select.select([sys.stdin], [], [], 0)[0]:
                    command = sys.stdin.readline().strip()
                    
                    if command == '/clear':
                        print("\n正在清除聊天记录...")
                        success = ChatService.clear_messages()
                        if success:
                            print("聊天记录已成功清除！\n")
                        else:
                            print("清除聊天记录失败！\n")
                    elif command == '/help':
                        print("\n终端命令列表：")
                        print("  /clear - 清除所有聊天记录")
                        print("  /help  - 显示帮助信息\n")
                    elif command:
                        print(f"\n未知命令: {command}")
                        print("输入/help查看可用命令\n")
        except Exception as e:
            print(f"\n处理命令时出错: {e}\n")

if __name__ == '__main__':
    # 启动终端输入处理线程
    terminal_thread = threading.Thread(target=handle_terminal_input, daemon=True)
    terminal_thread.start()
    
    # 启动Flask应用，禁用自动重载功能以避免终端输入问题
    app.run(host='0.0.0.0', port=5070, threaded=True, use_reloader=False)
