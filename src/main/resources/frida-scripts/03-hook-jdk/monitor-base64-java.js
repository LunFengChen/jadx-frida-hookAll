// Monitor Java Base64 operations (Java 8+)
// 监控 Java 标准 Base64 编解码
function hook_monitor_java_base64() {
    Java.perform(function () {
        console.log("[*] Starting Java Base64 monitoring...");
        
        var java_lang_String = Java.use('java.lang.String');
        
        // Helper function to print byte array in multiple formats
        function printByteArray(name, byteArray) {
            if (!byteArray) {
                console.log(name + ": null");
                return;
            }
            
            // 限制打印长度
            var maxLength = 100;
            var truncated = false;
            if (byteArray.length > maxLength) {
                byteArray = byteArray.slice(0, maxLength);
                truncated = true;
            }
            
            // 转换为十六进制字符串
            var hexString = "";
            for (var i = 0; i < byteArray.length; i++) {
                var hex = byteArray[i].toString(16);
                if (hex.length == 1) {
                    hex = "0" + hex;
                }
                hexString += hex;
                if (i < byteArray.length - 1) {
                    hexString += " ";
                }
            }
            if (truncated) {
                hexString += " ... (truncated)";
            }
            console.log(name + " (hex): " + hexString);
            
            // 尝试转换为字符串
            try {
                var str = java_lang_String.$new(byteArray, "UTF-8");
                console.log(name + " (str): " + str);
            } catch (e) {
                console.log(name + " (str): [not a valid UTF-8 string]");
            }
        }
        
        // Helper function to print stack trace
        function showJavaStacks() {
            try {
                console.log('Call stack:');
                var stackTrace = Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Throwable').$new());
                var lines = stackTrace.split('\n');
                for (var i = 1; i < Math.min(lines.length, 10); i++) { // Skip first line (current method)
                    console.log(lines[i]);
                }
            } catch (e) {
                console.log('Cannot get stack trace: ' + e.message);
            }
        }
        
        // Hook Java Standard Base64 (Java 8+)
        try {
            var java_util_Base64 = Java.use('java.util.Base64');
            var java_util_Base64_Encoder = Java.use('java.util.Base64$Encoder');
            var java_util_Base64_Decoder = Java.use('java.util.Base64$Decoder');
            
            // Java Base64.Encoder.encodeToString
            java_util_Base64_Encoder.encodeToString.overload('[B').implementation = function(input) {
                var result = this.encodeToString(input);
                console.log('\n================= Java Base64.Encoder.encodeToString =================');
                printByteArray('Input', input);
                console.log('Result: ' + result);
                showJavaStacks();
                return result;
            };
            
            // Java Base64.Encoder.encode
            java_util_Base64_Encoder.encode.overload('[B').implementation = function(input) {
                var result = this.encode(input);
                console.log('\n================= Java Base64.Encoder.encode =================');
                printByteArray('Input', input);
                printByteArray('Result', result);
                showJavaStacks();
                return result;
            };
            
            // Java Base64.Decoder.decode
            java_util_Base64_Decoder.decode.overload('[B').implementation = function(input) {
                var result = this.decode(input);
                console.log('\n================= Java Base64.Decoder.decode =================');
                printByteArray('Input', input);
                printByteArray('Result', result);
                showJavaStacks();
                return result;
            };
            
            java_util_Base64_Decoder.decode.overload('java.lang.String').implementation = function(str) {
                var result = this.decode(str);
                console.log('\n================= Java Base64.Decoder.decode =================');
                console.log('Input: ' + str);
                printByteArray('Result', result);
                showJavaStacks();
                return result;
            };
            
            console.log("[*] Java Standard Base64 hooked successfully");
        } catch (e) {
            console.log("[!] Java Standard Base64 not available: " + e.message);
        }
        
        console.log("[*] Java Base64 monitoring hooks installed successfully");
    });
}

// Execute the hook
hook_monitor_java_base64();
