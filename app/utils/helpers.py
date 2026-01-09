import os
import json
import re
from datetime import datetime
from ..config import Config

def ensure_directory_exists(directory):
    """确保目录存在，如果不存在则创建"""
    if not os.path.exists(directory):
        try:
            os.makedirs(directory, exist_ok=True)
            print(f'[INFO] 创建目录: {directory}')
            return True
        except Exception as e:
            print(f'[ERROR] 创建目录失败 {directory}: {str(e)}')
            return False
    return True

def validate_username(username, max_length=20, min_length=2):
    """验证用户名"""
    if not username or len(username) < min_length or len(username) > max_length:
        return False, f'用户名长度必须在{min_length}-{max_length}个字符之间'
    if not re.match(r'^[a-zA-Z0-9一-龥_]+$', username):
        return False, '用户名只能包含字母、数字、中文和下划线'
    return True, '用户名合法'

def load_json_file(file_path, default=None):
    """加载JSON文件"""
    if default is None:
        default = {}
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f'[INFO] 文件不存在: {file_path}')
        return default
    except json.JSONDecodeError as e:
        print(f'[ERROR] JSON文件解析错误 {file_path}: {str(e)}')
        return default

def save_json_file(file_path, data, indent=2):
    """保存JSON文件"""
    ensure_directory_exists(os.path.dirname(file_path))
    
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=indent)
        return True
    except Exception as e:
        print(f'[ERROR] 保存JSON文件失败 {file_path}: {str(e)}')
        return False

def backup_file(file_path):
    """备份文件"""
    if not os.path.exists(file_path):
        return None
    
    backup_path = f'{file_path}.backup.{datetime.now().strftime("%Y%m%d_%H%M%S")}'
    try:
        os.rename(file_path, backup_path)
        print(f'[INFO] 已备份文件为: {backup_path}')
        return backup_path
    except Exception as e:
        print(f'[ERROR] 备份文件失败 {file_path}: {str(e)}')
        return None

def cleanup_expired_items(items, expiration_key='expiration', current_time=None):
    """清理过期项目"""
    if current_time is None:
        current_time = datetime.now()
    
    expired_keys = []
    for key, item in items.items():
        # 检查item是否是字典，如果是则使用expiration_key获取过期时间，否则直接比较
        if isinstance(item, dict):
            if current_time >= item[expiration_key]:
                expired_keys.append(key)
        else:
            # 直接比较过期时间
            if current_time >= item:
                expired_keys.append(key)
    
    for key in expired_keys:
        del items[key]
    
    return expired_keys

def format_datetime(dt, format_str='%Y-%m-%d %H:%M:%S'):
    """格式化日期时间"""
    if isinstance(dt, str):
        dt = datetime.fromisoformat(dt)
    return dt.strftime(format_str)

def parse_datetime(dt_str):
    """解析日期时间字符串"""
    try:
        return datetime.fromisoformat(dt_str)
    except ValueError:
        return None
