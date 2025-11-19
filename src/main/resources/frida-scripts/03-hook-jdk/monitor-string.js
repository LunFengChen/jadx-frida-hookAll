// Monitor String operations
// 监控 String 操作（需要过滤，否则会很卡）
function showStacks() {
    console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
}

function hook_monitor_String() {
    Java.perform(function () {
        var String = Java.use('java.lang.String');
        var targetKeywords = [
            // 请求头相关
            "sign", "token", "auth", "authorization", "cookie", "session", 
            "x-sign", "x-token", "user-agent", "content-type", "accept",
            "referer", "host", "connection", "accept-encoding",
            
            // 参数相关
            "param", "data", "body", "query", "form", "json", "xml",
            "id", "uid", "userid", "username", "password", "phone", "email",
            "timestamp", "nonce", "version", "appkey", "secret",
            
            // 响应相关
            "code", "status", "message", "result", "data", "error", "success"
        ];

        // 辅助函数：检查字符串是否包含目标关键词
        function containsTargetKeywords(str) {
            if (!str) return false;
            var lowerStr = str.toLowerCase();
            for (var i = 0; i < targetKeywords.length; i++) {
                if (lowerStr.includes(targetKeywords[i])) {
                    return true;
                }
            }
            return false;
        }

        // 监控String构造函数
        String.$init.overload('[B').implementation = function(bytes) {
            var result = this.$init(bytes);
            var str = result.toString();
            if (containsTargetKeywords(str)) {
                console.log('\n================= String constructor(byte[]) =================');
                console.log('Content: ' + str);
                showStacks();
            }
            return result;
        };

        String.$init.overload('[C').implementation = function(chars) {
            var result = this.$init(chars);
            var str = result.toString();
            if (containsTargetKeywords(str)) {
                console.log('\n================= String constructor(char[]) =================');
                console.log('Content: ' + str);
                showStacks();
            }
            return result;
        };

        String.$init.overload('[B', 'java.lang.String').implementation = function(bytes, charsetName) {
            var result = this.$init(bytes, charsetName);
            var str = result.toString();
            if (containsTargetKeywords(str)) {
                console.log('\n================= String constructor(byte[], String) =================');
                console.log('Content: ' + str + ', Charset: ' + charsetName);
                showStacks();
            }
            return result;
        };

        // 监控concat方法
        String.concat.implementation = function(str) {
            var result = this.concat(str);
            var original = this.toString();
            if (containsTargetKeywords(original) || containsTargetKeywords(str)) {
                console.log('\n================= String.concat =================');
                console.log('Original: ' + original);
                console.log('Concatenated string: ' + str);
                console.log('Result: ' + result);
                showStacks();
            }
            return result;
        };

        // 监控replace方法
        String.replace.overload('java.lang.CharSequence', 'java.lang.CharSequence').implementation = function(target, replacement) {
            var result = this.replace(target, replacement);
            var original = this.toString();
            if (containsTargetKeywords(original) || containsTargetKeywords(target.toString()) || containsTargetKeywords(replacement.toString())) {
                console.log('\n================= String.replace =================');
                console.log('Original: ' + original);
                console.log('Target: ' + target);
                console.log('Replacement: ' + replacement);
                console.log('Result: ' + result);
                showStacks();
            }
            return result;
        };

        // 监控substring方法
        String.substring.overload('int').implementation = function(beginIndex) {
            var result = this.substring(beginIndex);
            var original = this.toString();
            if (containsTargetKeywords(original)) {
                console.log('\n================= String.substring =================');
                console.log('Original: ' + original);
                console.log('BeginIndex: ' + beginIndex);
                console.log('Result: ' + result);
                showStacks();
            }
            return result;
        };

        // 监控getBytes方法
        String.getBytes.overload().implementation = function () {
            var result = this.getBytes();
            if (this.toString().length == 32){
                // 可以利用长度进行过滤
                console.log('\n================= String.getBytes =================');
                var newStr = Java.use('java.lang.String').$new(result);
                console.log("str.getBytes result:", newStr);
                showStacks();
            }
            return result;
        }
    });

    console.warn(`[*] hook_monitor_String is injected`)
}

// Execute the hook
hook_monitor_String();
