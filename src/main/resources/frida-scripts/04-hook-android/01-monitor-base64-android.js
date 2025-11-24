// Monitor Android Base64 operations
// 监控 Android Base64 编解码
// android.util.Base64: Android提供的Base64工具类。
// 用途：二进制数据与字符串之间的编码转换。
// 逆向价值：**极高**。Base64常用于：
//           1. 简单的混淆（如将明文配置转为Base64）。
//           2. 加密前的准备（byte[] -> Base64 String）或解密后的展示。
//           3. 网络传输（图片、文件内容的传输）。
function hook_monitor_android_base64() {
    Java.perform(function () {
        console.log("[*] Starting Android Base64 monitoring...");

        // Hook Android Base64
        let android_util_Base64 = Java.use('android.util.Base64');
        let java_lang_String = Java.use('java.lang.String');

        // Helper function to print byte array in multiple formats
        function printByteArray(name, byteArray) {
            if (!byteArray) {
                console.log(name + ": null");
                return;
            }

            // 限制打印长度
            let maxLength = 100;
            let truncated = false;
            if (byteArray.length > maxLength) {
                byteArray = byteArray.slice(0, maxLength);
                truncated = true;
            }

            // 转换为十六进制字符串
            let hexString = "";
            for (let i = 0; i < byteArray.length; i++) {
                let hex = (byteArray[i] & 0xFF).toString(16);
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
                let str = java_lang_String.$new(byteArray, "UTF-8");
                // 简单的过滤：只打印看起来像文本的内容
                if (/^[\x20-\x7E]+$/.test(str)) {
                     console.log(name + " (str): " + str);
                } else {
                     console.log(name + " (str): [binary data or non-ascii]");
                }
            } catch (e) {
                console.log(name + " (str): [not a valid UTF-8 string]");
            }
        }

        // Helper function to print stack trace
        function showJavaStacks() {
            console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        }

        // Android Base64.encodeToString
        // 作用: byte[] -> String
        // 逆向场景：加密后的密文通常会转为Base64便于传输，Hook这里可以拿到加密后的二进制数据。
        android_util_Base64["encodeToString"].overload('[B', 'int').implementation = function (input, flags) {
            let result = this["encodeToString"](input, flags);
            console.log(`[->] android_util_Base64.encodeToString is called!`);
            printByteArray('    ->input', input);
            console.log(`    ->flags= ${flags}`);
            console.log(`    ->result= ${result}`);
            showJavaStacks();
            return result;
        };

        android_util_Base64["encodeToString"].overload('[B', 'int', 'int', 'int').implementation = function (input, offset, length, flags) {
            let result = this["encodeToString"](input, offset, length, flags);
            console.log(`[->] android_util_Base64.encodeToString is called!`);
            printByteArray('    ->input', input);
            console.log(`    ->offset= ${offset}`);
            console.log(`    ->length= ${length}`);
            console.log(`    ->flags= ${flags}`);
            console.log(`    ->result= ${result}`);
            showJavaStacks();
            return result;
        };

        // Android Base64.encode
        // 作用: byte[] -> byte[]
        // 逆向场景：同上，但返回的是字节数组。
        android_util_Base64["encode"].overload('[B', 'int').implementation = function (input, flags) {
            let result = this["encode"](input, flags);
            console.log(`[->] android_util_Base64.encode is called!`);
            printByteArray('    ->input', input);
            console.log(`    ->flags= ${flags}`);
            printByteArray('    ->result', result);
            showJavaStacks();
            return result;
        };

        android_util_Base64["encode"].overload('[B', 'int', 'int', 'int').implementation = function (input, offset, length, flags) {
            let result = this["encode"](input, offset, length, flags);
            console.log(`[->] android_util_Base64.encode is called!`);
            printByteArray('    ->input', input);
            console.log(`    ->offset= ${offset}`);
            console.log(`    ->length= ${length}`);
            console.log(`    ->flags= ${flags}`);
            printByteArray('    ->result', result);
            showJavaStacks();
            return result;
        };

        // Android Base64.decode
        // 作用: String/byte[] -> byte[]
        // 逆向场景：解密前的准备。通常服务器返回的加密数据是Base64格式，解密前需先Decode。Hook这里可以拿到待解密的密文。
        //           或者解码混淆字符串，直接看到明文。
        android_util_Base64["decode"].overload('[B', 'int').implementation = function (input, flags) {
            let result = this["decode"](input, flags);
            console.log(`[->] android_util_Base64.decode is called!`);
            printByteArray('    ->input', input);
            console.log(`    ->flags= ${flags}`);
            printByteArray('    ->result', result);
            showJavaStacks();
            return result;
        };

        android_util_Base64["decode"].overload('[B', 'int', 'int', 'int').implementation = function (input, offset, length, flags) {
            let result = this["decode"](input, offset, length, flags);
            console.log(`[->] android_util_Base64.decode is called!`);
            printByteArray('    ->input', input);
            console.log(`    ->offset= ${offset}`);
            console.log(`    ->length= ${length}`);
            console.log(`    ->flags= ${flags}`);
            printByteArray('    ->result', result);
            showJavaStacks();
            return result;
        };

        android_util_Base64["decode"].overload('java.lang.String', 'int').implementation = function (str, flags) {
            let result = this["decode"](str, flags);
            console.log(`[->] android_util_Base64.decode is called!`);
            console.log(`    ->str= ${str}`);
            console.log(`    ->flags= ${flags}`);
            printByteArray('    ->result', result);
            showJavaStacks();
            return result;
        };
    });
    console.warn(`[*] hook_monitor_android_base64 is injected!`);
};
hook_monitor_android_base64();
