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