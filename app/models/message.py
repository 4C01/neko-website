import os
import uuid
from datetime import datetime, timedelta
from collections import defaultdict
import threading
from ..config import Config
from ..utils.helpers import load_json_file, save_json_file, backup_file, ensure_directory_exists

# 聊天室相关变量
chat_rate_limits = defaultdict(list)  # 存储每个用户的消息发送时间
chat_lock = threading.Lock()  # 线程锁

class MessageModel:
    """消息模型"""
    
    @staticmethod
    def load_chat_config():
        """加载聊天室配置"""
        ensure_directory_exists(Config.CHATS_DIR)
        ensure_directory_exists(Config.USERS_DIR)
        ensure_directory_exists(Config.TEMPS_DIR)
        
        config = load_json_file(Config.CONFIG_FILE, default=Config.DEFAULT_CHAT_CONFIG)
        
        # 如果是默认配置，保存到文件
        if config == Config.DEFAULT_CHAT_CONFIG:
            save_json_file(Config.CONFIG_FILE, config, indent=4)
            print('[INFO] 已创建并保存默认配置文件')
        else:
            print('[INFO] 成功加载配置文件')
        
        return config
    
    @staticmethod
    def load_messages():
        """加载聊天消息"""
        ensure_directory_exists(Config.TEMPS_DIR)
        
        try:
            messages = load_json_file(Config.MESSAGES_FILE, default=[])
            print(f'[INFO] 成功加载 {len(messages)} 条聊天消息')
            return messages
        except Exception as e:
            print(f'[ERROR] 加载聊天消息失败: {str(e)}')
            return []
    
    @staticmethod
    def save_messages(messages):
        """保存聊天消息"""
        ensure_directory_exists(Config.TEMPS_DIR)
        
        if save_json_file(Config.MESSAGES_FILE, messages, indent=2):
            print(f'[INFO] 成功保存 {len(messages)} 条聊天消息')
            return True
        else:
            print(f'[ERROR] 保存聊天消息失败')
            return False
    
    @staticmethod
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
    
    @staticmethod
    def add_message(username, message):
        """添加新消息"""
        messages = MessageModel.load_messages()
        config = MessageModel.load_chat_config()
        
        # 检查消息长度
        max_length = config['chat']['max_message_length']
        if len(message) > max_length:
            return False, f'消息长度不能超过{max_length}个字符'
        
        # 创建新消息
        new_message = {
            'id': str(uuid.uuid4()),
            'username': username,
            'message': message,
            'timestamp': datetime.now().isoformat()
        }
        
        messages.append(new_message)
        
        # 检查消息数量，如果超过限制则清理
        max_messages = config['chat']['message_history_limit']
        cleanup_count = config['chat']['message_cleanup_threshold']
        
        if len(messages) > max_messages:
            messages = messages[cleanup_count:]
        
        if MessageModel.save_messages(messages):
            return True, new_message
        else:
            return False, '消息保存失败'
    
    @staticmethod
    def cleanup_old_messages():
        """清理过期消息"""
        try:
            config = MessageModel.load_chat_config()
            if not config['chat']['cleanup_schedule']['enabled']:
                return
            
            keep_days = config['chat']['cleanup_schedule']['keep_days']
            cutoff_date = datetime.now() - timedelta(days=keep_days)
            
            messages = MessageModel.load_messages()
            cleaned_messages = []
            
            for msg in messages:
                msg_date = datetime.fromisoformat(msg['timestamp'])
                if msg_date > cutoff_date:
                    cleaned_messages.append(msg)
            
            if len(cleaned_messages) != len(messages):
                MessageModel.save_messages(cleaned_messages)
                print(f'清理了 {len(messages) - len(cleaned_messages)} 条过期消息')
        except Exception as e:
            print(f'清理消息失败: {str(e)}')
    
    @staticmethod
    def init_cleanup_scheduler():
        """初始化清理计划任务"""
        import threading
        import time
        
        def cleanup_worker():
            while True:
                try:
                    config = MessageModel.load_chat_config()
                    if config.get('chat', {}).get('cleanup_schedule', {}).get('enabled', False):
                        interval_hours = config['chat']['cleanup_schedule'].get('interval_hours', 24)
                        MessageModel.cleanup_old_messages()
                        time.sleep(interval_hours * 3600)  # 转换为秒
                    else:
                        time.sleep(3600)  # 如果禁用清理，每小时检查一次
                except Exception as e:
                    print(f'清理任务错误: {str(e)}')
                    time.sleep(3600)
        
        # 在后台线程中运行清理任务
        cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
        cleanup_thread.start()
