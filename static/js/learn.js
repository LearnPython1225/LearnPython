// -----------------------------
// 左右面板宽度调整逻辑
// -----------------------------
(() => {
    const resizer = document.getElementById('resizer');
    const leftPanel = document.querySelector('.left-panel');
    const rightPanel = document.querySelector('.right-panel');
    let isResizing = false;

    resizer.addEventListener('mousedown', (e) => {
        // 当鼠标按下在分隔条上时开始调整宽度
        isResizing = true;
        // 暂时禁用文本选择与修改鼠标光标
        document.body.style.cursor = 'col-resize';
        document.body.style.userSelect = 'none';
        e.preventDefault(); // 避免选中文字等默认操作
    });

    document.addEventListener('mousemove', (e) => {
        if (!isResizing) return;
        const containerWidth = document.querySelector('.main-container').offsetWidth;
        const newLeftWidthPercent = (e.clientX / containerWidth) * 100;

        // 限制最小20%和最大80%
        if (newLeftWidthPercent > 20 && newLeftWidthPercent < 80) {
            leftPanel.style.flex = newLeftWidthPercent;
            rightPanel.style.flex = 100 - newLeftWidthPercent;
        }
    });

    document.addEventListener('mouseup', () => {
        if (isResizing) {
            isResizing = false;
            // 恢复可文本选择和默认鼠标样式
            document.body.style.cursor = 'default';
            document.body.style.userSelect = 'auto';

            // 重新布局Monaco Editor以适应新尺寸
            if (window.editor) {
                window.editor.layout();
            }
        }
    });

    // -----------------------------
    // 上下分割（Editor和Terminal）高度调整逻辑
    // -----------------------------
    const editorElement = document.getElementById('editor');
    const terminalElement = document.querySelector('.terminal');
    const resizerHorizontal = document.getElementById('resizer-horizontal');

    let isResizingHorizontal = false;

    resizerHorizontal.addEventListener('mousedown', (e) => {
        // 当鼠标在水平分隔条上按下时开始调整高度
        isResizingHorizontal = true;
        document.body.style.cursor = 'row-resize';
        document.body.style.userSelect = 'none';
        e.preventDefault(); // 同理，只阻止分隔条上的默认事件
    });

    document.addEventListener('mousemove', (e) => {
        if (!isResizingHorizontal) return;

        const containerHeight = document.querySelector('.editor-area').offsetHeight;
        const newEditorHeightPercent = (e.clientY / containerHeight) * 100;

        // 限制最小20%和最大80%
        if (newEditorHeightPercent > 20 && newEditorHeightPercent < 95) {
            editorElement.style.flex = `${newEditorHeightPercent}%`;
            terminalElement.style.flex = `${100 - newEditorHeightPercent}%`;
        }
    });

    document.addEventListener('mouseup', () => {
        if (isResizingHorizontal) {
            isResizingHorizontal = false;
            // 恢复正常
            document.body.style.cursor = 'default';
            document.body.style.userSelect = 'auto';

            // 重新布局Monaco Editor
            if (window.editor) {
                window.editor.layout();
            }
        }
    });

    document.getElementById('hideButton').addEventListener('click', function () {
        const leftBottom = document.querySelector('.left-bottom');
        const isHidden = leftBottom.classList.toggle('hidden'); // 切换hidden类
    
        // 更新按钮文本
        this.textContent = isHidden ? 'Show' : 'Hide';
    });

    document.addEventListener("DOMContentLoaded", () => {
        const hideButton = document.getElementById("hideButton");
        const chatContainer = document.querySelector(".chatgpt-container");
        const leftBottom = document.querySelector(".left-bottom");
        
        // 初始状态标志
        let isHidden = false;
    
        hideButton.addEventListener("click", () => {
            if (isHidden) {
                // 展开操作
                chatContainer.style.display = "flex"; // 恢复显示内容
                leftBottom.style.height = "600px"; // 还原高度
                hideButton.textContent = "Hide"; // 按钮文字改回
            } else {
                // 收缩操作
                chatContainer.style.display = "none"; // 隐藏内容
                leftBottom.style.height = "60px"; // 调整到仅显示标题高度
                hideButton.textContent = "Show"; // 按钮文字改为 Show
            }
            isHidden = !isHidden; // 切换状态
        });
    });

})();