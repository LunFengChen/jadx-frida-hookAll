// Monitor JSON operations (JSONObject, JSONArray)
// 监控 JSON 解析和构建
// org.json.JSONObject / org.json.JSONArray: Android内置的JSON处理类。
// 用途：构建和解析JSON数据。绝大多数App的网络请求参数和响应结果都是JSON格式。
// 逆向价值：**极高**。Hook JSON操作是目前最快定位业务逻辑数据的方法之一。
//           可以看到明文的请求体（在加密前）和响应体（在解密后）。
function hook_monitor_JSON() {
    Java.perform(function () {
        // 要监控的关键词
        let targetKeywords = [
            "sign", "token", "auth", "authorization", "key", "secret", "aes", "des", "rsa", "encrypt",
            "body", "param", "data", "response", "request", "code", "message"
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

        let org_json_JSONObject = Java.use("org.json.JSONObject");
        let org_json_JSONArray = Java.use("org.json.JSONArray");

        // 1. JSONObject 构造函数 (String)
        // 作用: 将JSON字符串解析为JSONObject对象。
        // 逆向场景：通常对应服务器响应数据的解析（解密后的明文）。
        org_json_JSONObject["$init"].overload('java.lang.String').implementation = function (json) {
            let result = this["$init"](json);
            if (containsTargetKeywords(json)) {
                console.log(`[->] org_json_JSONObject.$init(String) is called!`);
                console.log(`    ->json= ${json}`);
                showJavaStacks();
            }
            return result;
        };

        // 2. JSONObject.put
        // 作用: 向JSONObject中添加键值对。
        // 逆向场景：构建请求参数的过程，可以看到具体的Key-Value对。
        org_json_JSONObject["put"].overload('java.lang.String', 'java.lang.Object').implementation = function (key, value) {
            let result = this["put"](key, value);
            if (containsTargetKeywords(key) || containsTargetKeywords(value)) {
                console.log(`[->] org_json_JSONObject.put is called!`);
                console.log(`    ->key= ${key}`);
                console.log(`    ->value= ${value}`);
                // showJavaStacks();
            }
            return result;
        };

        // 3. JSONObject.getString
        // 作用: 从JSONObject中获取字符串值。
        // 逆向场景：读取服务器响应中的关键字段（如Token、Status）。
        org_json_JSONObject["getString"].implementation = function (key) {
            let result = this["getString"](key);
            if (containsTargetKeywords(key) || containsTargetKeywords(result)) {
                console.log(`[->] org_json_JSONObject.getString is called!`);
                console.log(`    ->key= ${key}`);
                console.log(`    ->result= ${result}`);
            }
            return result;
        };

        // 4. JSONArray 构造函数 (String)
        // 作用: 将JSON字符串解析为JSONArray对象。
        // 逆向场景：同JSONObject，用于解析列表类型的数据。
        org_json_JSONArray["$init"].overload('java.lang.String').implementation = function (json) {
            let result = this["$init"](json);
            if (containsTargetKeywords(json)) {
                console.log(`[->] org_json_JSONArray.$init(String) is called!`);
                console.log(`    ->json= ${json}`);
                showJavaStacks();
            }
            return result;
        };
    });
    console.warn(`[*] hook_monitor_JSON is injected!`);
}
hook_monitor_JSON();
