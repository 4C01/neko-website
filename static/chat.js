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
        this.loadedMessages = new Map(); // 记录已加载的消息，使用Map以便快速查找
        this.maxMessages = 100; // 最多显示100条消息
        
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

        // 处理特殊命令
        if (message === '/clear') {
            // 清除所有聊天记录
            this.clearChatHistory();
            return;
        }

        // 本地预先显示消息，提高用户体验
        const tempMessageId = 'temp-' + Date.now();
        this.addMessage(this.username, message, true, new Date().toISOString(), tempMessageId);

        // 发送消息到服务器
        this.simulateSendToServer(message, tempMessageId);
    }
    
    // 清除所有聊天记录
    clearChatHistory() {
        // 清空聊天消息区域（包括系统消息）
        const messages = this.chatMessages.querySelectorAll('.message, .system-message');
        messages.forEach(msg => msg.remove());
        
        // 清空已加载消息的记录
        this.loadedMessages.clear();
        this.lastMessageId = null;
        
        // 添加系统消息提示
        this.addSystemMessage('聊天记录已清除');
        
        // 设置标志，不再加载历史消息
        this.shouldLoadHistory = false;
        
        // 清除服务器端的聊天记录
        this.clearServerHistory();
    }
    
    // 清除服务器端的聊天记录
    async clearServerHistory() {
        try {
            const response = await fetch('/api/chat/clear', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                }
            });
            
            const result = await response.json();
            if (result.status === 'success') {
                console.log('服务器端聊天记录已清除');
            }
        } catch (error) {
            console.error('清除服务器端聊天记录失败:', error);
        }
    }

    async simulateSendToServer(message, tempMessageId) {
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
                // 删除本地临时消息
                this.removeTempMessage(tempMessageId);
            } else if (result.status === 'success') {
                // 服务器返回消息后，更新本地临时消息或直接使用服务器返回的消息
                this.removeTempMessage(tempMessageId);
                // 不需要立即刷新消息，等待定期刷新即可
                // 这样可以减少网络请求次数
            }
        } catch (error) {
            this.addSystemMessage('发送消息失败，请稍后重试');
            // 删除本地临时消息
            this.removeTempMessage(tempMessageId);
        }
    }
    
    // 删除临时消息
    removeTempMessage(tempMessageId) {
        const messageElement = document.getElementById(`msg-${tempMessageId}`);
        if (messageElement) {
            messageElement.remove();
            this.loadedMessages.delete(tempMessageId);
        }
    }

    addMessage(username, message, isOwn = false, timestamp = null, messageId = null) {
        // 如果消息ID已存在，不重复添加
        if (messageId && this.loadedMessages.has(messageId)) {
            return;
        }
        
        // 使用新的批量添加方法
        this.batchAddMessages([{
            id: messageId,
            username: username,
            message: message,
            timestamp: timestamp
        }]);
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
                let newMessages = data.messages;
                
                // 第一次加载，只显示最新的maxMessages条消息
                if (this.loadedMessages.size === 0) {
                    // 清空所有非系统消息
                    const messages = this.chatMessages.querySelectorAll('.message:not(.system-message)');
                    messages.forEach(msg => msg.remove());
                    
                    // 只保留最新的maxMessages条消息
                    if (newMessages.length > this.maxMessages) {
                        newMessages = newMessages.slice(-this.maxMessages);
                    }
                    
                    // 批量添加消息
                    this.batchAddMessages(newMessages);
                } else {
                    // 只加载新消息
                    const addedMessages = [];
                    newMessages.forEach(msg => {
                        if (!this.loadedMessages.has(msg.id)) {
                            addedMessages.push(msg);
                        }
                    });
                    
                    // 批量添加新消息
                    this.batchAddMessages(addedMessages);
                }
                
                this.updateOnlineCount(data.online_count || 1);
            }
        } catch (error) {
            console.error('加载聊天历史失败:', error);
        }
    }
    
    // 批量添加消息，减少DOM操作
    batchAddMessages(messages) {
        if (messages.length === 0) return;
        
        let messagesFragment = document.createDocumentFragment();
        
        messages.forEach(msg => {
            if (!this.loadedMessages.has(msg.id)) {
                const messageElement = this.createMessageElement(msg.username, msg.message, msg.username === this.username, msg.timestamp, msg.id);
                messagesFragment.appendChild(messageElement);
                this.loadedMessages.set(msg.id, msg);
                this.lastMessageId = msg.id;
            }
        });
        
        // 将批量创建的消息添加到DOM中
        this.chatMessages.appendChild(messagesFragment);
        
        // 检查消息数量，超过限制则删除旧消息
        this.limitMessageCount();
        
        // 滚动到底部
        this.scrollToBottom();
    }
    
    // 创建消息元素但不立即添加到DOM
    createMessageElement(username, message, isOwn = false, timestamp = null, messageId = null) {
        const messageElement = document.createElement('div');
        messageElement.className = `message ${isOwn ? 'own' : ''}`;
        
        // 为消息元素添加唯一ID
        if (messageId) {
            messageElement.id = `msg-${messageId}`;
        }

        const avatar = document.createElement('img');
        avatar.className = 'message-avatar';
        avatar.src = '/static/default_avatar.png';
        avatar.alt = username;
        avatar.style.borderRadius = '50%';
        avatar.style.width = '40px';
        avatar.style.height = '40px';
        avatar.style.objectFit = 'cover';

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
        
        return messageElement;
    }
    
    // 限制消息数量
    limitMessageCount() {
        const messages = this.chatMessages.querySelectorAll('.message:not(.system-message)');
        const excess = messages.length - this.maxMessages;
        
        if (excess > 0) {
            // 删除最早的excess条消息
            for (let i = 0; i < excess; i++) {
                const messageElement = messages[i];
                const messageId = messageElement.id.replace('msg-', '');
                
                // 从Map中删除
                this.loadedMessages.delete(messageId);
                
                // 从DOM中删除
                messageElement.remove();
            }
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