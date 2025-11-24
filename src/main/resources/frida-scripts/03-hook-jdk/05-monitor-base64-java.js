// Monitor Java Base64 operations (Java 8+)
// 监控 Java 标准 Base64 编解码 (java.util.Base64)
// 
// 功能增强：
// 1. 全量打印: 不截断长字符串，完整显示 Hex 和 String。
// 2. 智能过滤: 同时检查“输入数据”和“输出数据”是否包含目标关键词。
// 3. 堆栈追踪: 只要触发关键词过滤，就打印堆栈。

function hook_monitor_java_base64() {
    
    // ========================================================================
    // 配置区域
    // ========================================================================
    const config = {
        // 关键词过滤 (空数组表示不过滤，监控所有)
        // 会同时匹配：明文、Base64字符串
        keywords: [
            "sign", "token", "auth", "key", "secret", "aes", "des", "rsa",
            "password", "pwd", "session", "user", "uid", "timestamp"
        ]
    };

    Java.perform(function () {
        console.log("[*] Starting Java Base64 monitoring...");
        
        let Base64 = Java.use('java.util.Base64');
        let Encoder = Java.use('java.util.Base64$Encoder');
        let Decoder = Java.use('java.util.Base64$Decoder');
        let java_lang_String = Java.use('java.lang.String');
        let Log = Java.use("android.util.Log");
        let Exception = Java.use("java.lang.Exception");

        // ====================================================================
        // 工具函数
        // ====================================================================

        // Helper function to print stack trace
        function showJavaStacks() {
            console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        }

        // 将 Java byte[] 转为 JS string (UTF-8)
        function bytesToString(bytes) {
            if (bytes === null) return "(null)";
            try {
                return java_lang_String.$new(bytes, "UTF-8").toString();
            } catch(e) {
                return "[Not UTF-8]";
            }
        }
        
        // 将 Java byte[] 转为 Hex 字符串
        function bytesToHex(bytes) {
            if (bytes === null) return "(null)";
            let hex = "";
            for (let i = 0; i < bytes.length; i++) {
                let b = bytes[i];
                if (b < 0) b += 256; // 处理有符号字节
                let h = b.toString(16);
                if (h.length === 1) h = "0" + h;
                hex += h;
            }
            return hex;
        }

        // 核心过滤逻辑
        // data 可以是 byte[] 或 String
        function isInteresting(data) {
            if (config.keywords.length === 0) return true; // 没配关键词就全看
            if (data === null) return false;
            
            let str = "";
            if (typeof data === 'string') {
                str = data;
            } else { // assume byte[]
                str = bytesToString(data); // 尝试转字符串匹配
            }
            
            let lowerStr = str.toLowerCase();
            for (let k of config.keywords) {
                if (lowerStr.includes(k)) return true;
            }
            return false;
        }

        // ====================================================================
        // Hook Logic
        // ====================================================================

        // 1. Hook Encoder.encode(byte[]) -> byte[]
        Encoder.encode.overload('[B').implementation = function (src) {
            let result = this.encode(src);
            
            // 检查 输入(明文) 或 输出(密文/Base64 bytes) 是否包含关键词
            // 注意：输出是 Base64 编码后的 bytes，转成 String 就是 Base64 串
            let srcStr = bytesToString(src);
            let resStr = bytesToString(result); // 这就是 Base64 字符串
            
            if (isInteresting(srcStr) || isInteresting(resStr)) {
                console.log("\n[Base64.Encoder.encode] Found interesting data!");
                console.log("    Input (Plain):  " + srcStr);
                console.log("    Output(Base64): " + resStr);
                // console.log("    Output(Hex):    " + bytesToHex(result)); // 如果需要看Hex
                showJavaStacks();
            }
            return result;
        };
        
        // 2. Hook Encoder.encodeToString(byte[]) -> String
        // 这是最常用的 API
        Encoder.encodeToString.overload('[B').implementation = function (src) {
            let result = this.encodeToString(src);
            
            let srcStr = bytesToString(src);
            
            if (isInteresting(srcStr) || isInteresting(result)) {
                console.log("\n[Base64.Encoder.encodeToString] Found interesting data!");
                console.log("    Input (Plain):  " + srcStr);
                console.log("    Output(Base64): " + result);
                showJavaStacks();
            }
            return result;
        };

        // 3. Hook Decoder.decode(byte[]) -> byte[]
        Decoder.decode.overload('[B').implementation = function (src) {
            let result = this.decode(src);
            
            let srcStr = bytesToString(src); // Base64 串
            let resStr = bytesToString(result); // 解码后的明文
            
            if (isInteresting(srcStr) || isInteresting(resStr)) {
                console.log("\n[Base64.Decoder.decode(byte[])] Found interesting data!");
                console.log("    Input (Base64): " + srcStr);
                console.log("    Output(Plain):  " + resStr);
                console.log("    Output(Hex):    " + bytesToHex(result));
                showJavaStacks();
            }
            return result;
        };

        // 4. Hook Decoder.decode(String) -> byte[]
        Decoder.decode.overload('java.lang.String').implementation = function (src) {
            let result = this.decode(src);
            
            let resStr = bytesToString(result); // 解码后的明文
            
            if (isInteresting(src) || isInteresting(resStr)) {
                console.log("\n[Base64.Decoder.decode(String)] Found interesting data!");
                console.log("    Input (Base64): " + src);
                console.log("    Output(Plain):  " + resStr);
                console.log("    Output(Hex):    " + bytesToHex(result));
                showJavaStacks();
            }
            return result;
        };
        
    });
    console.warn('[*] hook_monitor_java_base64 injected');
}
hook_monitor_java_base64();

/*
关于 Java 标准 Base64 的详解

从 Java 8 开始，JDK 终于提供了一个标准的 Base64 实现：`java.util.Base64`。
在此之前，Android 开发通常使用 `android.util.Base64`，或者第三方的 `sun.misc.BASE64Encoder` (不推荐)。

主要内部类：
1. `java.util.Base64.Encoder`: 编码器 (byte[] -> Base64)
   - `encode(byte[])`: 返回 byte[]
   - `encodeToString(byte[])`: 返回 String (最常用)

2. `java.util.Base64.Decoder`: 解码器 (Base64 -> byte[])
   - `decode(byte[])`: 输入 byte[]
   - `decode(String)`: 输入 String (最常用)

逆向注意：
- 如果 App 设置了 `minSdkVersion >= 26` (Android 8.0)，开发者可能会混用 `java.util.Base64` 和 `android.util.Base64`。
- 很多第三方库（如 OkHttp, Retrofit 内部）可能会自带 Base64 实现，或者使用这个 Java 标准版，而不是 Android 版。
- 所以，如果你 Hook `android.util.Base64` 没抓到数据，一定要试试这个！

速记：
1. 这是纯 Java 的 Base64，跟 Android 无关。
2. 高版本 Android APP 或者用了大量 Java 第三方库的 APP，经常用这个。
3. 它的 API 风格是 `getEncoder().encodeToString()`，不同于 Android 的 `Base64.encodeToString()` 静态方法。
*/
