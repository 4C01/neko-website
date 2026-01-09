from ..models.user import UserModel
from ..utils.helpers import validate_username

class UserService:
    """用户服务"""
    
    @staticmethod
    def create_user(username, password):
        """创建新用户"""
        # 验证用户名
        valid, msg = validate_username(username)
        if not valid:
            return False, msg
        
        # 创建用户
        return UserModel.create_user(username, password)
    
    @staticmethod
    def verify_user(username, password):
        """验证用户凭据"""
        return UserModel.verify_user(username, password)
    
    @staticmethod
    def get_user(username):
        """获取用户信息"""
        user_data = UserModel.load_user(username)
        if user_data:
            return True, user_data
        else:
            return False, '用户不存在'
    
    @staticmethod
    def update_user(username, updates):
        """更新用户信息"""
        return UserModel.update_user(username, updates)
    
    @staticmethod
    def delete_user(username):
        """删除用户"""
        return UserModel.delete_user(username)
