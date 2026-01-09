import os
from datetime import datetime
from ..config import Config
from ..utils.helpers import load_json_file, save_json_file, backup_file
from ..utils.security import hash_password, verify_password

class UserModel:
    """用户模型"""
    
    @staticmethod
    def get_user_file(username):
        """获取用户文件路径"""
        return os.path.join(Config.USERS_DIR, f'{username}.json')
    
    @staticmethod
    def load_user(username):
        """加载用户信息"""
        user_file = UserModel.get_user_file(username)
        user_data = load_json_file(user_file)
        
        if user_data:
            print(f'[INFO] 成功加载用户: {username}')
            return user_data
        else:
            print(f'[INFO] 用户不存在: {username}')
            return None
    
    @staticmethod
    def save_user(username, user_data):
        """保存用户信息"""
        user_file = UserModel.get_user_file(username)
        
        if save_json_file(user_file, user_data):
            print(f'[INFO] 成功保存用户数据: {username}')
            return True
        else:
            print(f'[ERROR] 保存用户数据失败 {username}')
            return False
    
    @staticmethod
    def create_user(username, password):
        """创建新用户"""
        # 检查用户是否已存在
        if UserModel.load_user(username):
            return False, '用户名已存在'
        
        # 创建用户数据
        user_data = {
            'username': username,
            'password_hash': hash_password(password),
            'created_at': datetime.now().isoformat(),
            'last_login': None
        }
        
        if UserModel.save_user(username, user_data):
            return True, '用户创建成功'
        else:
            return False, '用户创建失败'
    
    @staticmethod
    def verify_user(username, password):
        """验证用户凭据"""
        user_data = UserModel.load_user(username)
        if not user_data:
            return False, '用户不存在'
        
        if verify_password(password, user_data['password_hash']):
            # 更新最后登录时间
            user_data['last_login'] = datetime.now().isoformat()
            UserModel.save_user(username, user_data)
            return True, '登录成功'
        else:
            return False, '密码错误'
    
    @staticmethod
    def update_user(username, updates):
        """更新用户信息"""
        user_data = UserModel.load_user(username)
        if not user_data:
            return False, '用户不存在'
        
        user_data.update(updates)
        
        if UserModel.save_user(username, user_data):
            return True, '用户信息更新成功'
        else:
            return False, '用户信息更新失败'
    
    @staticmethod
    def delete_user(username):
        """删除用户"""
        user_file = UserModel.get_user_file(username)
        
        if os.path.exists(user_file):
            try:
                os.remove(user_file)
                print(f'[INFO] 成功删除用户: {username}')
                return True, '用户删除成功'
            except Exception as e:
                print(f'[ERROR] 删除用户失败 {username}: {str(e)}')
                return False, '用户删除失败'
        else:
            return False, '用户不存在'
