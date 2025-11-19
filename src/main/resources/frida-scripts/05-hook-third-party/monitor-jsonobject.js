// Monitor JSONObject operations (important for request/response body)
// 监控 JSONObject 操作（处理请求体和响应体加密）
function showJavaStacks() {
    console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
}

function hook_monitor_JSONObject() {
    Java.perform(function () {
        let JSONObject = Java.use("org.json.JSONObject");
        
        // 要监控的关键词列表
        let targetKeywords = [
            // 认证相关
            "sign", "token", "auth", "authorization", "secret", "key",
            // 用户信息相关
            "user", "uid", "username", "password", "phone", "email",
            // 业务相关
            "blacklist", "naturechannel", "status", "code", "message",
            // 数据相关
            "data", "info", "result", "config", "setting"
        ];
        
        // 辅助函数：检查字符串是否包含目标关键词
        function containsTargetKeyword(str) {
            if (!str) return false;
            
            let lowerStr = str.toLowerCase();
            for (let keyword of targetKeywords) {
                if (lowerStr.includes(keyword)) {
                    return true;
                }
            }
            return false;
        }
        
        // 1. 构造函数
        JSONObject.$init.overload().implementation = function() {
            console.log(`\n================= JSONObject.<init>() =================`);
            showJavaStacks();
            return this.$init();
        };
        
        JSONObject.$init.overload('java.lang.String').implementation = function(json) {
            console.log(`\n================= JSONObject.<init>(String) =================`);
            console.log(`JSON string: ${json ? json.substring(0, 100) + (json.length > 100 ? '...' : '') : 'null'}`);
            showJavaStacks();
            return this.$init(json);
        };
        
        // 2. put方法
        JSONObject.put.overload('java.lang.String', 'java.lang.Object').implementation = function(key, value) {
            let result = this.put(key, value);
            
            if (containsTargetKeyword(key) || (value && containsTargetKeyword(value.toString()))) {
                console.log(`\n================= JSONObject.put =================`);
                console.log(`Key: ${key}`);
                console.log(`Value: ${value}`);
                showJavaStacks();
            }
            
            return result;
        };
        
        // 3. getString方法
        JSONObject.getString.implementation = function(key) {
            let result = this.getString(key);
            
            if (containsTargetKeyword(key) || containsTargetKeyword(result)) {
                console.log(`\n================= JSONObject.getString =================`);
                console.log(`Key: ${key}`);
                console.log(`Value: ${result}`);
                showJavaStacks();
            }
            
            return result;
        };
        
        // 4. optString方法
        JSONObject.optString.overload('java.lang.String').implementation = function(key) {
            let result = this.optString(key);
            
            if (containsTargetKeyword(key) || containsTargetKeyword(result)) {
                console.log(`\n================= JSONObject.optString =================`);
                console.log(`Key: ${key}`);
                console.log(`Value: ${result}`);
                showJavaStacks();
            }
            
            return result;
        };
        
        // 5. getBoolean方法
        JSONObject.getBoolean.overload('java.lang.String').implementation = function(key) {
            let result = this.getBoolean(key);
            
            if (containsTargetKeyword(key)) {
                console.log(`\n================= JSONObject.getBoolean =================`);
                console.log(`Key: ${key}`);
                console.log(`Value: ${result}`);
                
                // 特殊处理blackList字段
                if (key === 'blackList') {
                    console.log("[*] 检测到blackList字段，强制返回false");
                    return false;
                }
                
                showJavaStacks();
            }
            
            return result;
        };
        
        // 6. optBoolean方法
        JSONObject.optBoolean.overload('java.lang.String', 'boolean').implementation = function(key, defaultValue) {
            let result = this.optBoolean(key, defaultValue);
            
            if (containsTargetKeyword(key)) {
                console.log(`\n================= JSONObject.optBoolean(default) =================`);
                console.log(`Key: ${key}`);
                console.log(`Default value: ${defaultValue}`);
                console.log(`Result value: ${result}`);
                
                // 特殊处理isNatureChannel字段
                if (key === 'isNatureChannel') {
                    console.log("[*] 检测到isNatureChannel字段，强制返回false");
                    return false;
                }
                
                showJavaStacks();
            }
            
            return result;
        };
        
        // 7. toString方法
        JSONObject.toString.overload().implementation = function() {
            let result = this.toString();
            console.log(`\n================= JSONObject.toString =================`);
            console.log(`JSON content: ${result.length > 200 ? result.substring(0, 200) + '...' : result}`);
            showJavaStacks();
            return result;
        };
    });
    console.warn(`[*] hook_monitor_JSONObject is injected`);
}

// 执行钩子
hook_monitor_JSONObject();
