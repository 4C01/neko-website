from ..models.message import MessageModel
from ..models.user import UserModel
from ..utils.helpers import validate_username

class ChatService:
    """聊天室服务"""
    
    @staticmethod
    def register_user(username, password):
        """注册聊天室用户"""
        # 验证用户名
        valid, msg = validate_username(username)
        if not valid:
            return False, msg
        
        # 验证密码长度
        config = MessageModel.load_chat_config()
        min_length = config['security']['password_min_length']
        if len(password) < min_length:
            return False, f'密码长度至少{min_length}位'
        
        # 创建用户
        success, message = UserModel.create_user(username, password)
        return success, message
    
    @staticmethod
    def login_user(username, password):
        """聊天室用户登录"""
        return UserModel.verify_user(username, password)
    
    @staticmethod
    def get_messages():
        """获取聊天消息"""
        messages = MessageModel.load_messages()
        
        # 简单的在线人数统计（最近20条消息中的唯一用户名数量）
        recent_users = set()
        for msg in messages[-20:]:
            recent_users.add(msg['username'])
        online_count = len(recent_users)
        
        return messages, online_count
    
    @staticmethod
    def send_message(username, message):
        """发送聊天消息"""
        # 加载配置
        config = MessageModel.load_chat_config()
        
        # 检查速率限制
        if not MessageModel.check_rate_limit(username, config):
            return False, f'发送太频繁，每分钟最多发送{config["rate_limit"]["messages_per_minute"]}条消息'
        
        # 添加消息
        success, result = MessageModel.add_message(username, message)
        return success, result
    
    @staticmethod
    def load_chat_config():
        """加载聊天室配置"""
        return MessageModel.load_chat_config()
    
    @staticmethod
    def cleanup_old_messages():
        """清理过期消息"""
        MessageModel.cleanup_old_messages()
    
    @staticmethod
    def init_cleanup_scheduler():
        """初始化清理计划任务"""
        MessageModel.init_cleanup_scheduler()
    
    @staticmethod
    def clear_messages():
        """清除所有聊天消息"""
        try:
            # 保存空列表到消息文件，实现清除
            return MessageModel.save_messages([])
        except Exception as e:
            print(f'[ERROR] 清除聊天消息失败: {str(e)}')
            return False
