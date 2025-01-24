// -----------------------------
// ChatGPT 交互逻辑类
// -----------------------------
(() => {
class Chat {
    constructor() {
        // 获取必要的DOM元素
        this.sendBtn = document.getElementById('sendBtn');
        this.userMessageInput = document.getElementById('userMessage');
        this.chatMessages = document.getElementById('chatMessages');

        // 初始化事件监听器
        this.setupEventListeners();
    }

    setupEventListeners() {
        // 点击发送按钮时发送消息
        this.sendBtn.addEventListener('click', () => this.sendMessage());

        // 在输入框中按回车键时也发送消息（若按钮未禁用）
        this.userMessageInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter' && !this.sendBtn.disabled) {
                this.sendMessage();
            }
        });

        this.displayMessage('Hello! How can I assist you with Python today?');

    }

    async sendMessage() {
        const message = this.userMessageInput.value.trim();
        if (!message) return;

        // 显示用户消息
        this.displayMessage("You: " + message, 'user-message');
        
        // 清空输入框并禁用输入与按钮（防止重复操作）
        this.userMessageInput.value = '';
        this.sendBtn.disabled = true;
        this.userMessageInput.disabled = true;

        // 显示加载中提示
        this.showLoading();

        try {
            // 向后端发送请求
            const response = await fetch('/chatgpt', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message })
            });


            if (response.status === 429) {
                // 显示错误信息
                throw new Error(`You have reached the daily usage limit!`);
            }

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }


            


            const result = await response.json();

            

            if (result.status === 'success') {
                // 返回成功后显示来自ChatGPT的回复（支持HTML渲染）
                this.displayMessage(result.reply, 'chatgpt-message', true);
            } else {
                throw new Error(result.message || 'Unknown error occurred');
            }
        } catch (error) {
            console.error('Error:', error);
            // 显示错误信息
            this.displayMessage("Error: " + error.message, 'error-message');
        } finally {
            // 移除加载中提示并恢复输入框和按钮的使用
            this.hideLoading();
            this.sendBtn.disabled = false;
            this.userMessageInput.disabled = false;
        }
    }

    /**
     * 显示消息在聊天窗口中
     * @param {string} message 显示的文本内容
     * @param {string} className 用于区分消息类型的类名
     * @param {boolean} isHTML 是否将message作为HTML插入
     */
    displayMessage(message, className, isHTML = false) {
        const msgElem = document.createElement('div');
        msgElem.className = className;

        if (isHTML) {
            msgElem.innerHTML = message;
        } else {
            msgElem.textContent = message;
        }

        this.chatMessages.appendChild(msgElem);
        // 自动滚动到底部
        this.chatMessages.scrollTop = this.chatMessages.scrollHeight;
    }

    /**
     * 显示"ChatGPT is thinking..."的加载中提示
     */
    showLoading() {
        const loadingElem = document.createElement('div');
        loadingElem.textContent = "AI is thinking...";
        loadingElem.className = 'loading-message';
        loadingElem.id = 'loadingIndicator';
        this.chatMessages.appendChild(loadingElem);
        this.chatMessages.scrollTop = this.chatMessages.scrollHeight;
    }

    /**
     * 隐藏加载中提示
     */
    hideLoading() {
        const loadingElem = document.getElementById('loadingIndicator');
        if (loadingElem) {
            loadingElem.remove();
        }
    }
}

// 页面加载完毕后初始化Chat实例
document.addEventListener('DOMContentLoaded', () => {
    new Chat();
});
})();



