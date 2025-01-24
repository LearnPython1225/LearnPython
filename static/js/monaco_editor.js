require.config({ paths: { 'vs': 'https://cdnjs.cloudflare.com/ajax/libs/monaco-editor/0.33.0/min/vs' }});

require(['vs/editor/editor.main'], function () {
    const PYTHON_KEYWORDS = [
        'False', 'None', 'True', 'and', 'as', 'assert', 'async', 'await', 'break', 'class', 'continue',
        'def', 'del', 'elif', 'else', 'except', 'finally', 'for', 'from', 'global', 'if', 'import',
        'in', 'is', 'lambda', 'nonlocal', 'not', 'or', 'pass', 'raise', 'return', 'try', 'while', 'with', 'yield'
    ];

    const PYTHON_BUILTINS = [
        'abs','dict','help','min','setattr','all','dir','hex','next','slice','any','divmod','id','object','sorted','ascii',
        'enumerate','input','oct','staticmethod','bin','eval','int','open','str','bool','exec','isinstance','ord','sum','bytearray',
        'filter','issubclass','pow','super','bytes','float','iter','print','tuple','callable','format','len','property','type',
        'chr','frozenset','list','range','vars','classmethod','getattr','locals','repr','zip','compile','globals','map','reversed','__import__',
        'complex','hasattr','max','round','delattr','hash','memoryview','set'
    ];

    // Monarch语法定义：为类名、函数名、decorator、内置函数等分配特定token
    monaco.languages.setMonarchTokensProvider('python', {
        defaultToken: '',
        tokenPostfix: '.python',
        keywords: PYTHON_KEYWORDS,
        builtins: PYTHON_BUILTINS,

        // 使用正则匹配定义行，以识别class和def后的标识符为class名或function名
        // 使用states或在root中优先匹配:
        tokenizer: {
            root: [
                // Decorators: 行首@后跟标识符
                [/^([ \t]*)@([A-Za-z_]\w*)/, ['','','meta.decorator']],

                // class定义: class后跟 类名
                [/^([ \t]*)(class)(\s+)([A-Za-z_]\w*)/,
                    [
                        '',        // whitespace不加token
                        'keyword', // class关键字
                        '',        // 空白
                        'type.class' // 类名token
                    ]
                ],

                // def定义: def后跟 函数名
                [/^([ \t]*)(def)(\s+)([A-Za-z_]\w*)/,
                    [
                        '',
                        'keyword',     // def关键字
                        '',
                        'type.function' // 函数名token
                    ]
                ],

                [/[ \t\r\n]+/, ''],
                [/#.*$/, 'comment'],
                [/('''|""")/, { token: 'string', next: '@mstring' }],
                [/"/, { token: 'string', next: '@string_double' }],
                [/'/, { token: 'string', next: '@string_single' }],

                [/\d+\.\d+([eE][+\-]?\d+)?j?/, 'number'],
                [/\d+[eE][+\-]?\d+j?/, 'number'],
                [/0[oO]?[0-7]+j?/, 'number'],
                [/0[xX][0-9a-fA-F]+j?/, 'number'],
                [/0[bB][0-1]+j?/, 'number'],
                [/\d+j?/, 'number'],

                // 标识符：判断是否为keyword、builtin
                [/[A-Za-z_]\w*/, {
                    cases: {
                        '@keywords': 'keyword',
                        '@builtins': 'support.function', // 内置函数记为support.function
                        '@default': 'identifier'         // 普通变量名
                    }
                }],

                [/[+\-*/%=&|<>!~^@]+/, 'operator'],
                [/[()[\]{}]/, 'delimiter.bracket']
            ],

            mstring: [
                [/'''/, 'string', '@pop'],
                [/"""/, 'string', '@pop'],
                [/./, 'string']
            ],
            string_double: [
                [/\\./, 'string.escape'],
                [/"/, 'string', '@pop'],
                [/./, 'string']
            ],
            string_single: [
                [/\\./, 'string.escape'],
                [/'/, 'string', '@pop'],
                [/./, 'string']
            ]
        }
    });

    // 定义主题并赋予相应颜色
    monaco.editor.defineTheme('vscode-dark-plus', {
        base: 'vs-dark',
        inherit: true,
        rules: [
            { token: 'keyword', foreground: '569CD6', fontStyle: 'bold' },
            { token: 'support.function', foreground: '4EC9B0'}, // 内置函数绿色
            { token: 'string', foreground: 'CE9178' },
            { token: 'comment', foreground: '6A9955', fontStyle: 'italic' },
            { token: 'number', foreground: 'B5CEA8' },
            { token: 'operator', foreground: 'D4D4D4' },
            { token: 'identifier', foreground: '9CDCFE' }, // 普通标识符浅蓝
            { token: 'type.class', foreground: '4EC9B0', fontStyle: 'bold' }, // 类名绿色
            { token: 'type.function', foreground: 'DCDCAA', fontStyle: 'bold' }, // 函数名黄色
            { token: 'meta.decorator', foreground: 'C586C0' }, // 装饰器紫色
            { token: 'delimiter.bracket', foreground: 'DCDCAA' } // 括号黄色
        ],
        colors: {
            'editor.background': '#1E1E1E',
            'editorLineNumber.foreground': '#858585',
            'editorCursor.foreground': '#FFFFFF',
            'editorIndentGuide.background': '#404040'
        }
    });

    window.editor = monaco.editor.create(document.getElementById('editor'), {
        value: '# Start coding here\n\nif True:\n    print("Hello!")\nelse:\n    print("Not greater than 9")',
        language: 'python',
        theme: 'vscode-dark-plus',
        automaticLayout: true
    });

    // 简单错误检查：检查需要冒号的语句
    function checkPythonErrors() {
        const code = window.editor.getValue();
        const lines = code.split('\n');
        const errors = [];
        const colonNeeded = /^(if|elif|else|for|while|def|class|try|except|finally)\b/;

        lines.forEach((line, i) => {
            const trimmed = line.trim();
            if (colonNeeded.test(trimmed) && !trimmed.endsWith(':')) {
                errors.push({
                    message: `Syntax Error: Missing ":" after ${trimmed.split(/\s+/)[0]} statement`,
                    severity: monaco.MarkerSeverity.Error,
                    startLineNumber: i + 1,
                    startColumn: 1,
                    endLineNumber: i + 1,
                    endColumn: line.length + 1
                });
            }
        });

        monaco.editor.setModelMarkers(window.editor.getModel(), 'owner', errors);
    }

    checkPythonErrors();
    window.editor.onDidChangeModelContent(() => {
        checkPythonErrors();
    });

    // 自动补全
    monaco.languages.registerCompletionItemProvider('python', {
        provideCompletionItems: () => {
            const suggestions = [];

            PYTHON_KEYWORDS.forEach(kw => {
                suggestions.push({
                    label: kw,
                    kind: monaco.languages.CompletionItemKind.Keyword,
                    insertText: kw + ' ',
                    detail: 'Python Keyword'
                });
            });

            PYTHON_BUILTINS.forEach(fn => {
                suggestions.push({
                    label: fn,
                    kind: monaco.languages.CompletionItemKind.Function,
                    insertText: fn + '(${1:args})',
                    insertTextRules: monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet,
                    detail: 'Python Built-in'
                });
            });

            const commonModules = ['os', 'sys', 'json', 're', 'math', 'datetime', 'random'];
            commonModules.forEach(mod => {
                suggestions.push({
                    label: mod,
                    kind: monaco.languages.CompletionItemKind.Module,
                    insertText: mod,
                    detail: 'Common Python module'
                });
            });

            return { suggestions };
        }
    });


    // Update the run code event listener
    document.getElementById('runCode').addEventListener('click', async () => {
        const code = window.editor.getValue();
        const terminalOutput = document.getElementById('terminalOutput');
        
        try {
            // Validate code before sending to server
            securityUtils.validateCode(code);
            
            // Check rate limit
            const userId = document.querySelector('meta[name="user-id"]')?.content || 'anonymous';
            securityUtils.createRateLimiter()(userId);

            terminalOutput.textContent = "Running...";

            const response = await fetch('/run_code', {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': document.querySelector('meta[name="csrf-token"]')?.content
                },
                body: JSON.stringify({ code })
            });

            if (!response.ok) {
                throw new Error(`Server error: ${response.statusText}`);
            }

            const result = await response.json();
            
            // Sanitize output before displaying
            terminalOutput.textContent = securityUtils.sanitizeOutput(result.output || result.error || "No output returned.");
            
        } catch (error) {
            terminalOutput.textContent = `Error: ${error.message}`;
        }
    });

    // Add execution timeout
    const executeWithTimeout = async (code, timeout = 5000) => {
        return Promise.race([
            fetch('/run_code', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ code })
            }),
            new Promise((_, reject) => 
                setTimeout(() => reject(new Error('Execution timeout')), timeout)
            )
        ]);
    };

});





document.getElementById('clearTerminal').addEventListener('click', () => {
    const terminalOutput = document.getElementById('terminalOutput');
    terminalOutput.textContent = ""; // 清空终端内容
});