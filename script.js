// 创建彩球的函数
function createBubbles() {
    const bubbleCount = 100; // 增加彩球数量
    const container = document.body;
    
    for (let i = 0; i < bubbleCount; i++) {
        const bubble = document.createElement('div');
        bubble.classList.add('bubble');
        
        // 随机大小
        const size = Math.random() * 100 + 20;
        bubble.style.width = `${size}px`;
        bubble.style.height = `${size}px`;
        
        // 随机颜色（偏暗的半透明颜色）
        const colors = [
            'rgba(120, 80, 100, 0.3)',
            'rgba(90, 100, 130, 0.3)',
            'rgba(100, 120, 90, 0.3)',
            'rgba(130, 90, 110, 0.3)',
            'rgba(80, 110, 120, 0.3)'
        ];
        const color = colors[Math.floor(Math.random() * colors.length)];
        bubble.style.backgroundColor = color;
        // 随机水平位置
        bubble.style.left = `${Math.random() * 100}%`;
        bubble.style.top = `${Math.random() * 100}%`;
        
        // 随机延迟
        bubble.style.animationDelay = `${Math.random() * 10}s`;
        
        container.appendChild(bubble);
        
        // 在动画结束后移除泡泡
        setTimeout(() => {
            if (bubble.parentNode) {
                bubble.parentNode.removeChild(bubble);
            }
        }, 11000); // 动画持续时间11秒
    }
}

// 页面加载完成后创建彩球，并设置循环
window.addEventListener('load', function() {
    createBubbles();
    // 每隔一段时间重新创建彩球，实现循环效果
    setInterval(createBubbles, 5000);
});

// 响应式功能：根据屏幕大小控制元素显示
function handleResponsive() {
    const contentCards = document.querySelector('.content-cards');
    const buttonSpan = document.querySelector('.box-button span');
    const boxImage = document.querySelector('.box-image');
    const boxImageImg = document.querySelector('.box-image img');
    
    if (contentCards && buttonSpan && boxImage && boxImageImg) {
        // 获取屏幕宽度
        const screenWidth = window.innerWidth;
        
        // 当屏幕宽度小于800px时，隐藏box-image
        if (screenWidth <= 800) {
            contentCards.style.display = 'none';
            buttonSpan.style.display = 'none';
        // 当屏幕宽度小于600px时，将图片src改为icon.png
            if (screenWidth <= 600) {
                boxImageImg.src = 'icon.png';
                boxImage.style.display = 'block';
            } else {
                boxImageImg.src = '';
                boxImage.style.display = 'none';
            }
        } else {
            boxImageImg.src = 'neko.png';
            boxImage.style.display = 'block';
            contentCards.style.display = 'flex';
            buttonSpan.style.display = 'inline';
        }
    }
}

// 页面加载时执行响应式处理
window.addEventListener('load', handleResponsive);

// 窗口大小改变时执行响应式处理
window.addEventListener('resize', handleResponsive);

// 登录弹出框功能
window.addEventListener('load', function() {
    const loginButton = document.getElementById('loginButton');
    const loginModal = document.getElementById('loginModal');
    const closeModal = document.querySelector('.close');
    const modalLoginButton = document.getElementById('modalLoginButton');
    const passwordInput = document.getElementById('passwordInput');
    const message = document.getElementById('message');
    
    // 显示弹出框
    loginButton.addEventListener('click', function() {
        loginModal.style.display = 'block';
        passwordInput.value = '';
        message.textContent = '';
    });
    
    // 关闭弹出框
    closeModal.addEventListener('click', function() {
        loginModal.style.display = 'none';
    });
    
    // 点击弹出框外部关闭
    window.addEventListener('click', function(event) {
        if (event.target === loginModal) {
            loginModal.style.display = 'none';
        }
    });
    
    // 登录验证
    modalLoginButton.addEventListener('click', function() {
        const password = passwordInput.value;
        if (password) {
            // 访问认证服务
            fetch(`http://auth.4c01.cn/login?pwd=${password}`)
                .then(response => response.text())
                .then(data => {
                    if (data.startsWith('http')) {
                        // 如果返回的是http地址，直接跳转
                        window.location.href = data;
                    } else {
                        // 否则显示返回的消息
                        message.textContent = data;
                    }
                })
                .catch(error => {
                    message.textContent = '登录请求失败';
                    console.error('Error:', error);
                });
        } else {
            message.textContent = '请输入密码';
        }
    });
});