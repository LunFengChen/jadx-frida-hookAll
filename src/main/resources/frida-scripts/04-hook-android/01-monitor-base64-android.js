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
            // let maxLength = 100;
            let truncated = false;
            // if (byteArray.length > maxLength) {
            //     byteArray = byteArray.slice(0, maxLength);
            //     truncated = true;
            // }

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

/*
关于 Base64 的详解

Base64 是一种基于64个可打印字符来表示二进制数据的表示方法。

核心原理：
将 3 个字节 (3 * 8 = 24 bits) 的二进制数据，划分为 4 个组 (4 * 6 = 24 bits)。
每个组 6 bits，值范围 0-63，对应码表中的一个字符。
如果数据长度不是3的倍数，使用 '=' 进行填充 (Padding)。

标准码表 (RFC 4648)：
A-Z (26) + a-z (26) + 0-9 (10) + '+' (1) + '/' (1) = 64 个字符
填充字符：'='

常见变种：
1. URL Safe Base64:
   - 将 '+' 替换为 '-' (减号)
   - 将 '/' 替换为 '_' (下划线)
   - 目的：避免在 URL 中引起歧义（+变空格，/变路径分隔符）。

2. 自定义码表 (魔改 Base64):
   - 逆向中非常常见！
   - 算法逻辑不变，只是打乱了索引表的顺序，或者替换了几个字符。
   - 识别方法：找到 encode/decode 函数，查看其引用的 64 字节长的字符串常量。

开发中常用的：

需求场景                推荐方案                                原因
标准传输                Base64.DEFAULT                         最通用
URL参数                 Base64.URL_SAFE                        防止URL转义问题
不换行                  Base64.NO_WRAP                         避免长文本自动换行(\n)
忽略填充                Base64.NO_PADDING                      有些协议不需要等号

速记：
1. 看到 "==" 或 "=" 结尾的字符串，第一时间怀疑是 Base64。
2. 看到 "ABCDEFGHIJKLMNOPQRSTUVWXYZ..." 这种字符串，就是 Base64 码表。
3. 逆向时如果解密失败，检查一下是不是用了 URL Safe 模式 (-_) 或者自定义码表。
4. new String(bytes) 乱码时，试试 Base64.encodeToString(bytes) 看看能不能看懂。
*/
