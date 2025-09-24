// 聊天室JavaScript功能
class ChatRoom {
    constructor() {
        this.chatToken = localStorage.getItem('chatToken') || '';
        this.username = localStorage.getItem('chatUsername') || '';
        this.userId = this.generateUserId();
        this.ws = null;
        this.isTyping = false;
        this.typingTimeout = null;
        this.onlineUsers = new Set();
        this.lastMessageId = null; // 记录最后一条消息的ID
        this.loadedMessages = new Set(); // 记录已加载的消息ID
        
        this.initElements();
        this.initEventListeners();
        this.checkAuth();
        this.connectWebSocket();
    }

    initElements() {
        this.chatMessages = document.getElementById('chatMessages');
        this.messageInput = document.getElementById('messageInput');
        this.usernameInput = document.getElementById('usernameInput');
        this.sendButton = document.getElementById('sendButton');
        this.onlineCount = document.getElementById('onlineCount');
        this.typingIndicator = document.getElementById('typingIndicator');
        this.typingUsers = document.getElementById('typingUsers');
    }

    initEventListeners() {
        // 发送按钮点击事件
        this.sendButton.addEventListener('click', () => this.sendMessage());
        
        // 回车发送消息
        this.messageInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                this.sendMessage();
            }
        });

        // 昵称输入事件
        this.usernameInput.addEventListener('input', () => {
            this.username = this.usernameInput.value.trim();
            localStorage.setItem('chatUsername', this.username);
            this.updateSendButtonState();
        });

        // 输入框自动调整高度
        this.messageInput.addEventListener('input', () => {
            this.autoResizeTextarea();
            this.handleTyping();
        });

        // 失去焦点时停止输入状态
        this.messageInput.addEventListener('blur', () => {
            this.stopTyping();
        });
    }

    generateUserId() {
        return 'user_' + Math.random().toString(36).substr(2, 9);
    }

    loadUsername() {
        if (this.username) {
            // 禁用用户名输入框，因为已经通过认证
            this.usernameInput.value = this.username;
            this.usernameInput.disabled = true;
            this.usernameInput.style.backgroundColor = 'rgba(0, 0, 0, 0.7)';
            this.usernameInput.style.color = '#ccc';
        }
        this.updateSendButtonState();
    }

    checkAuth() {
        // 检查聊天室认证
        if (!this.chatToken || !this.username) {
            alert('需要先登录聊天室');
            window.location.href = '/chat/auth';
            return;
        }
        this.loadUsername();
    }

    updateSendButtonState() {
        const hasUsername = this.username.length > 0;
        const hasMessage = this.messageInput.value.trim().length > 0;
        this.sendButton.disabled = !hasUsername || !hasMessage;
    }

    autoResizeTextarea() {
        this.messageInput.style.height = 'auto';
        this.messageInput.style.height = Math.min(this.messageInput.scrollHeight, 120) + 'px';
        this.updateSendButtonState();
    }

    connectWebSocket() {
        // 由于这是一个真实的聊天室，使用HTTP API代替WebSocket
        this.simulateWebSocketConnection();
            
        // 添加页面关闭时清理定时器
        window.addEventListener('beforeunload', () => {
            if (this.messageRefreshInterval) {
                clearInterval(this.messageRefreshInterval);
            }
        });
    }

    simulateWebSocketConnection() {
        // 连接到聊天服务器
        this.addSystemMessage('正在连接到聊天服务器...');
        this.loadChatHistory();
        this.updateOnlineCount(1);
        
        // 定期刷新消息（减少到5秒一次）
        this.messageRefreshInterval = setInterval(() => {
            this.loadChatHistory();
        }, 5000);
    }

    sendMessage() {
        const message = this.messageInput.value.trim();
        if (!message || !this.username) return;

        // 清空输入框
        this.messageInput.value = '';
        this.autoResizeTextarea();
        this.updateSendButtonState();

        // 停止输入状态
        this.stopTyping();

        // 直接发送到服务器，不在本地预先显示
        this.simulateSendToServer(message);
    }

    async simulateSendToServer(message) {
        // 发送消息到服务器
        try {
            const response = await fetch('/api/chat/send', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    message: message
                })
            });
            
            const result = await response.json();
            if (result.status === 'error') {
                this.addSystemMessage(result.message);
            } else if (result.status === 'success') {
                // 发送成功后立即刷新消息
                this.loadChatHistory();
            }
        } catch (error) {
            this.addSystemMessage('发送消息失败，请稍后重试');
        }
    }

    addMessage(username, message, isOwn = false, timestamp = null, messageId = null) {
        // 如果消息ID已存在，不重复添加
        if (messageId && document.getElementById(`msg-${messageId}`)) {
            return;
        }
        
        const messageElement = document.createElement('div');
        messageElement.className = `message ${isOwn ? 'own' : ''}`;
        
        // 为消息元素添加唯一ID
        if (messageId) {
            messageElement.id = `msg-${messageId}`;
        }

        const avatar = document.createElement('div');
        avatar.className = 'message-avatar';
        avatar.textContent = username.charAt(0).toUpperCase();

        const content = document.createElement('div');
        content.className = 'message-content';

        const info = document.createElement('div');
        info.className = 'message-info';

        const usernameSpan = document.createElement('span');
        usernameSpan.className = 'message-username';
        usernameSpan.textContent = username;

        const timeSpan = document.createElement('span');
        timeSpan.className = 'message-time';
        if (timestamp) {
            const date = new Date(timestamp);
            timeSpan.textContent = date.toLocaleTimeString('zh-CN', {
                hour: '2-digit',
                minute: '2-digit'
            });
        } else {
            timeSpan.textContent = new Date().toLocaleTimeString('zh-CN', {
                hour: '2-digit',
                minute: '2-digit'
            });
        }

        info.appendChild(usernameSpan);
        info.appendChild(timeSpan);

        const text = document.createElement('div');
        text.className = 'message-text';
        text.textContent = this.processMessage(message);

        content.appendChild(info);
        content.appendChild(text);

        messageElement.appendChild(avatar);
        messageElement.appendChild(content);

        this.chatMessages.appendChild(messageElement);
        this.scrollToBottom();
    }

    addSystemMessage(message) {
        const systemMessage = document.createElement('div');
        systemMessage.className = 'system-message';
        systemMessage.textContent = message;
        this.chatMessages.appendChild(systemMessage);
        this.scrollToBottom();
    }

    processMessage(message) {
        // 直接返回原消息，不做任何转换
        return message;
    }

    handleTyping() {
        if (!this.isTyping && this.messageInput.value.trim()) {
            this.isTyping = true;
            // 在真实应用中，这里会通过WebSocket发送输入状态
        }

        // 清除之前的超时
        clearTimeout(this.typingTimeout);

        // 设置新的超时，3秒后停止输入状态
        this.typingTimeout = setTimeout(() => {
            this.stopTyping();
        }, 3000);
    }

    stopTyping() {
        if (this.isTyping) {
            this.isTyping = false;
            clearTimeout(this.typingTimeout);
            // 在真实应用中，这里会通过WebSocket发送停止输入状态
        }
    }

    updateOnlineCount(count) {
        this.onlineCount.textContent = `在线: ${count}`;
    }

    scrollToBottom() {
        this.chatMessages.scrollTop = this.chatMessages.scrollHeight;
    }

    // 加载聊天历史记录
    async loadChatHistory() {
        try {
            const response = await fetch('/api/chat/messages');
            const data = await response.json();
            
            if (data.status === 'success') {
                const newMessages = data.messages;
                
                // 第一次加载，清空现有消息区域（除了系统消息）
                if (this.loadedMessages.size === 0) {
                    // 清空所有非系统消息
                    const messages = this.chatMessages.querySelectorAll('.message:not(.system-message)');
                    messages.forEach(msg => msg.remove());
                    
                    // 加载所有消息
                    newMessages.forEach(msg => {
                        this.addMessage(msg.username, msg.message, msg.username === this.username, msg.timestamp, msg.id);
                        this.loadedMessages.add(msg.id);
                        this.lastMessageId = msg.id;
                    });
                } else {
                    // 只加载新消息
                    newMessages.forEach(msg => {
                        if (!this.loadedMessages.has(msg.id)) {
                            this.addMessage(msg.username, msg.message, msg.username === this.username, msg.timestamp, msg.id);
                            this.loadedMessages.add(msg.id);
                            this.lastMessageId = msg.id;
                        }
                    });
                }
                
                this.updateOnlineCount(data.online_count || 1);
            }
        } catch (error) {
            console.error('加载聊天历史失败:', error);
        }
    }

    // 公共方法：添加新用户加入消息
    addUserJoinedMessage(username) {
        this.addSystemMessage(`${username} 加入了聊天室`);
    }

    // 公共方法：添加用户离开消息
    addUserLeftMessage(username) {
        this.addSystemMessage(`${username} 离开了聊天室`);
    }

    // 公共方法：显示输入状态
    showTypingIndicator(users) {
        if (users.length > 0) {
            const userList = users.join(', ');
            this.typingUsers.textContent = `${userList} 正在输入`;
            this.typingIndicator.style.display = 'flex';
        } else {
            this.typingIndicator.style.display = 'none';
        }
    }
}

// 页面加载完成后初始化聊天室
document.addEventListener('DOMContentLoaded', () => {
    // 检查认证状态
    const token = localStorage.getItem('token') || getCookie('auth_token');
    
    if (!token) {
        // 未认证用户重定向到登录页面
        alert('请先登录后再进入聊天室');
        window.location.href = '/login';
        return;
    }

    // 初始化聊天室
    window.chatRoom = new ChatRoom();
});

// Cookie 工具函数
function getCookie(name) {
    const nameEQ = name + "=";
    const ca = document.cookie.split(';');
    for(let i = 0; i < ca.length; i++) {
        let c = ca[i];
        while (c.charAt(0) == ' ') c = c.substring(1, c.length);
        if (c.indexOf(nameEQ) == 0) return c.substring(nameEQ.length, c.length);
    }
    return null;
}

// 页面可见性变化处理
document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
        // 页面隐藏时的处理
        if (window.chatRoom) {
            window.chatRoom.stopTyping();
        }
    } else {
        // 页面显示时的处理
        if (window.chatRoom) {
            window.chatRoom.scrollToBottom();
        }
    }
});

// 窗口大小变化时调整滚动位置
window.addEventListener('resize', () => {
    if (window.chatRoom) {
        setTimeout(() => {
            window.chatRoom.scrollToBottom();
        }, 100);
    }
});

// 防止页面刷新时丢失输入内容
window.addEventListener('beforeunload', (e) => {
    const messageInput = document.getElementById('messageInput');
    if (messageInput && messageInput.value.trim()) {
        e.preventDefault();
        e.returnValue = '您有未发送的消息，确定要离开吗？';
    }
});