// Monitor StringBuilder and StringBuffer (String concatenation)
// 监控字符串拼接
// java.lang.StringBuilder/StringBuffer: 可变的字符序列。
// 用途：高效地进行字符串拼接、修改。StringBuilder是非线程安全的（更快），StringBuffer是线程安全的。
// 逆向价值：**中等**。很多加密算法或协议生成过程中，会使用StringBuilder拼接参数、签名或密文。
//           Hook toString() 往往能直接看到拼接完成后的最终结果（如完整的URL、完整的JSON、拼接好的签名明文）。
function hook_monitor_StringBuilder() {
    Java.perform(function () {
        // 要监控的关键词
        let targetKeywords = [
            "sign", "token", "auth", "authorization", "key", "secret", "aes", "des", "rsa", "encrypt",
            "body", "param", "data", "response", "request"
        ];

        // 辅助函数：检查是否包含目标关键词
        function containsTargetKeywords(str) {
            if (!str) return false;
            let lowerStr = str.toString().toLowerCase();
            for (let i = 0; i < targetKeywords.length; i++) {
                if (lowerStr.includes(targetKeywords[i])) {
                    return true;
                }
            }
            return false;
        }

        // Helper function to print stack trace
        function showJavaStacks() {
            console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        }

        // 监控构造函数 (String)
        // 作用: 初始化 StringBuilder。
        // 逆向场景：查看初始值（如URL前缀、JSON开头）。
        java_lang_StringBuilder["$init"].overload('java.lang.String').implementation = function (str) {
            let result = this["$init"](str);
            if (containsTargetKeywords(str)) {
                console.log(`[->] java_lang_StringBuilder.$init(String) is called!`);
                console.log(`    ->str= ${str}`);
                showJavaStacks();
            }
            return result;
        };

        // 字符串拼接 - StringBuilder
        // 监控 toString 方法
        // 作用：将构建好的字符序列转换为 String。
        // 逆向场景：在参数签名计算前，通常会把所有参数拼接成一个字符串，这里通常是查看明文的最佳时机。
        let java_lang_StringBuilder = Java.use("java.lang.StringBuilder");
        java_lang_StringBuilder["toString"].implementation = function () {
            let result = this["toString"]();
            if (containsTargetKeywords(result)) {
                console.log(`[->] java_lang_StringBuilder.toString is called!`);
                console.log(`    ->result= ${result}`);
                showJavaStacks(); 
            }
            return result;
        };

        // 监控 append 方法 (String)
        // 作用：追加字符串。
        // 逆向场景：监控拼接过程中的每一个片段。
        java_lang_StringBuilder["append"].overload('java.lang.String').implementation = function (str) {
            let result = this["append"](str);
            if (containsTargetKeywords(str)) {
                console.log(`[->] java_lang_StringBuilder.append(String) is called!`);
                console.log(`    ->str= ${str}`);
                // showJavaStacks(); // Append calls are very frequent, stack trace might be too noisy here
            }
            return result;
        };

        // 监控 insert 方法 (String)
        // 作用: 插入字符串。
        // 逆向场景：监控在特定位置插入参数的操作。
        java_lang_StringBuilder["insert"].overload('int', 'java.lang.String').implementation = function (offset, str) {
            let result = this["insert"](offset, str);
            if (containsTargetKeywords(str)) {
                console.log(`[->] java_lang_StringBuilder.insert(int, String) is called!`);
                console.log(`    ->offset= ${offset}`);
                console.log(`    ->str= ${str}`);
                // showJavaStacks();
            }
            return result;
        };

        // 监控 replace 方法 (String)
        // 作用: 替换字符串。
        // 逆向场景：监控修改数据的操作。
        java_lang_StringBuilder["replace"].overload('int', 'int', 'java.lang.String').implementation = function (start, end, str) {
            let result = this["replace"](start, end, str);
            if (containsTargetKeywords(str)) {
                console.log(`[->] java_lang_StringBuilder.replace(int, int, String) is called!`);
                console.log(`    ->start= ${start}`);
                console.log(`    ->end= ${end}`);
                console.log(`    ->str= ${str}`);
                showJavaStacks();
            }
            return result;
        };

        // 支持多线程 字符串拼接 - StringBuffer
        // 同 StringBuilder，但用于多线程环境
        let java_lang_StringBuffer = Java.use("java.lang.StringBuffer");
        java_lang_StringBuffer["toString"].implementation = function () {
            let result = this["toString"]();
            if (containsTargetKeywords(result)) {
                console.log(`[->] java_lang_StringBuffer.toString is called!`);
                console.log(`    ->result= ${result}`);
                showJavaStacks();
            }
            return result;
        };

        // 监控 append 方法 (String)
        java_lang_StringBuffer["append"].overload('java.lang.String').implementation = function (str) {
            let result = this["append"](str);
            if (containsTargetKeywords(str)) {
                console.log(`[->] java_lang_StringBuffer.append(String) is called!`);
                console.log(`    ->str= ${str}`);
                // showJavaStacks();
            }
            return result;
        };
        // 监控 insert 方法 (String)
        java_lang_StringBuffer["insert"].overload('int', 'java.lang.String').implementation = function (offset, str) {
            let result = this["insert"](offset, str);
            if (containsTargetKeywords(str)) {
                console.log(`[->] java_lang_StringBuffer.insert(int, String) is called!`);
                console.log(`    ->offset= ${offset}`);
                console.log(`    ->str= ${str}`);
                // showJavaStacks();
            }
            return result;
        };

        // 监控 replace 方法 (String)
        java_lang_StringBuffer["replace"].overload('int', 'int', 'java.lang.String').implementation = function (start, end, str) {
            let result = this["replace"](start, end, str);
            if (containsTargetKeywords(str)) {
                console.log(`[->] java_lang_StringBuffer.replace(int, int, String) is called!`);
                console.log(`    ->start= ${start}`);
                console.log(`    ->end= ${end}`);
                console.log(`    ->str= ${str}`);
                showJavaStacks();
            }
            return result;
        };
    });
    console.warn(`[*] hook_monitor_StringBuilder is injected!`);
};
hook_monitor_StringBuilder();
