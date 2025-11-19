// Monitor Android Base64 operations
// 监控 Android Base64 编解码
function hook_monitor_android_base64() {
    Java.perform(function () {
        console.log("[*] Starting Android Base64 monitoring...");

        // Hook Android Base64
        var android_util_Base64 = Java.use('android.util.Base64');
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
            console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        }

        // Android Base64.encodeToString
        android_util_Base64.encodeToString.overload('[B', 'int').implementation = function (input, flags) {
            var result = this.encodeToString(input, flags);
            console.log('\n================= Android Base64.encodeToString =================');
            printByteArray('Input', input);
            console.log('Flags: ' + flags);
            console.log('Result: ' + result);
            showJavaStacks();
            return result;
        };

        android_util_Base64.encodeToString.overload('[B', 'int', 'int', 'int').implementation = function (input, offset, length, flags) {
            var result = this.encodeToString(input, offset, length, flags);
            console.log('\n================= Android Base64.encodeToString =================');
            printByteArray('Input', input);
            console.log('Offset: ' + offset);
            console.log('Length: ' + length);
            console.log('Flags: ' + flags);
            console.log('Result: ' + result);
            showJavaStacks();
            return result;
        };

        // Android Base64.encode
        android_util_Base64.encode.overload('[B', 'int').implementation = function (input, flags) {
            var result = this.encode(input, flags);
            console.log('\n================= Android Base64.encode =================');
            printByteArray('Input', input);
            console.log('Flags: ' + flags);
            printByteArray('Result', result);
            showJavaStacks();
            return result;
        };

        android_util_Base64.encode.overload('[B', 'int', 'int', 'int').implementation = function (input, offset, length, flags) {
            var result = this.encode(input, offset, length, flags);
            console.log('\n================= Android Base64.encode =================');
            printByteArray('Input', input);
            console.log('Offset: ' + offset);
            console.log('Length: ' + length);
            console.log('Flags: ' + flags);
            printByteArray('Result', result);
            showJavaStacks();
            return result;
        };

        // Android Base64.decode
        android_util_Base64.decode.overload('[B', 'int').implementation = function (input, flags) {
            var result = this.decode(input, flags);
            console.log('\n================= Android Base64.decode =================');
            printByteArray('Input', input);
            console.log('Flags: ' + flags);
            printByteArray('Result', result);
            showJavaStacks();
            return result;
        };

        android_util_Base64.decode.overload('[B', 'int', 'int', 'int').implementation = function (input, offset, length, flags) {
            var result = this.decode(input, offset, length, flags);
            console.log('\n================= Android Base64.decode =================');
            printByteArray('Input', input);
            console.log('Offset: ' + offset);
            console.log('Length: ' + length);
            console.log('Flags: ' + flags);
            printByteArray('Result', result);
            showJavaStacks();
            return result;
        };

        android_util_Base64.decode.overload('java.lang.String', 'int').implementation = function (str, flags) {
            var result = this.decode(str, flags);
            console.log('\n================= Android Base64.decode =================');
            console.log('Input: ' + str);
            console.log('Flags: ' + flags);
            printByteArray('Result', result);
            showJavaStacks();
            return result;
        };
    });
    console.log("[*] hook_monitor_android_base64 is injected");
}

// Execute the hook
hook_monitor_android_base64();
