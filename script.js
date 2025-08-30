// 创建彩球的函数
function createBubbles() {
    const bubbleCount = 40; // 增加彩球数量
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
    }
}

// 页面加载完成后创建彩球，并设置循环
window.addEventListener('load', function() {
    createBubbles();
    // 每隔一段时间重新创建彩球，实现循环效果
    setInterval(createBubbles, 5000);
});

// 页面加载完成后创建彩球
window.addEventListener('load', createBubbles);

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
        // 当屏幕宽度小于600px时，将图片src改为icon.jpg
            if (screenWidth <= 600) {
                boxImageImg.src = 'icon.jpg';
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