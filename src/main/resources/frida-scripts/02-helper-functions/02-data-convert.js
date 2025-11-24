// 功能：常用数据格式互转 - 字节数组、十六进制、字符串、Base64 互转

// ==================== 字节数组 <-> 十六进制 ====================

// 字节数组转十六进制字符串
function bytesToHex(bytes) {
    var hex = '';
    for (var i = 0; i < bytes.length; i++) {
        hex += ('0' + (bytes[i] & 0xFF).toString(16)).slice(-2);
    }
    return hex;
}

// 十六进制字符串转字节数组
function hexToBytes(hex) {
    var bytes = [];
    for (var i = 0; i < hex.length; i += 2) {
        bytes.push(parseInt(hex.substr(i, 2), 16));
    }
    return bytes;
}

// ==================== 字节数组 <-> 字符串 ====================

// 字节数组转 UTF-8 字符串 (推荐)
function bytesToString(bArr) {
    var JDKClass_String = Java.use('java.lang.String');
    return JDKClass_String.$new(Java.array('byte', bArr)).toString();
}

// 字节数组转 UTF-8 字符串 (使用 Charset)
function bytesToUtf8(exampleBytes) {
    var JDKClass_String = Java.use("java.lang.String");
    var JDKClass_Charset = Java.use("java.nio.charset.Charset");
    var utf8Charset = JDKClass_Charset.forName("UTF-8");
    return JDKClass_String.$new(exampleBytes, utf8Charset);
}

// 字符串转字节数组
function stringToBytes(str) {
    var JDKClass_String = Java.use("java.lang.String");
    return JDKClass_String.$new(str).getBytes();
}

// ==================== 字节数组 <-> Base64 ====================

// 字节数组转 Base64 字符串
function bytesToBase64(bytes) {
    var AndroidClass_Base64 = Java.use("android.util.Base64");
    return AndroidClass_Base64.encodeToString(bytes, 0);
}

// Base64 字符串转字节数组
function base64ToBytes(base64Str) {
    var AndroidClass_Base64 = Java.use("android.util.Base64");
    var JDKClass_String = Java.use("java.lang.String");
    return AndroidClass_Base64.decode(JDKClass_String.$new(base64Str), 0);
}

// ==================== 十六进制 <-> 字符串 ====================

// 十六进制字符串转 UTF-8 字符串
function hexToString(hex) {
    return bytesToString(hexToBytes(hex));
}

// UTF-8 字符串转十六进制字符串
function stringToHex(str) {
    return bytesToHex(stringToBytes(str));
}

// ==================== Base64 <-> 字符串 ====================

// Base64 字符串转 UTF-8 字符串
function base64ToString(base64Str) {
    return bytesToString(base64ToBytes(base64Str));
}

// UTF-8 字符串转 Base64 字符串
function stringToBase64(str) {
    return bytesToBase64(stringToBytes(str));
}

// ==================== 特殊转换 ====================

// 使用 ByteString 转 UTF-8 (需要 okhttp 库)
function bytesToUtf8_ByteString(bArr) {
    var OkHttpClass_ByteString = Java.use("com.android.okhttp.okio.ByteString");
    return OkHttpClass_ByteString.of(bArr).utf8();
}

// 使用 Java.cast 转换数组
function bytesToUtf8_Cast(objArr) {
    var JDKClass_Byte = Java.use("[B");
    var buffer = Java.cast(objArr[0], JDKClass_Byte);
    var res = Java.array('byte', buffer);
    return res;
}

// ==================== 辅助函数 ====================

// 打印所有格式的数据
function printAllFormats(bytes, dataName) {
    console.log((dataName || "Data") + " in all formats:");
    console.log("  Hex:    " + bytesToHex(bytes));
    console.log("  String: " + bytesToString(bytes));
    console.log("  Base64: " + bytesToBase64(bytes));
}

// 注意事项：
// 1. bytesToString 是最简单的字节转字符串方法，推荐使用
// 2. bytesToHex 适用于查看原始字节的十六进制表示
// 3. Base64 编码常用于网络传输和存储
// 4. bytesToUtf8_ByteString 需要应用中有 okhttp 库
// 5. 所有转换都假设字符编码为 UTF-8

// 使用示例:
// function hook_monitor_encrypt(){
//     Java.perform(function () {
//         let com_example_Crypto = Java.use("com.example.Crypto");
//         com_example_Crypto["encrypt"].implementation = function (data) {
//             console.log(`[->] com_example_Crypto.encrypt is called! args are as follows:`);
//             console.log(`    ->data(Hex)= ${bytesToHex(data)}`);
//             console.log(`    ->data(String)= ${bytesToString(data)}`);
//             console.log(`    ->data(Base64)= ${bytesToBase64(data)}`);
//             
//             var retval = this["encrypt"](data);
//             
//             console.log(`[<-] com_example_Crypto.encrypt ended!`);
//             console.log(`    retval(Hex)= ${bytesToHex(retval)}`);
//             console.log(`    retval(String)= ${bytesToString(retval)}`);
//             console.log(`    retval(Base64)= ${bytesToBase64(retval)}`);
//             
//             // 或者使用 printAllFormats 一次性打印所有格式
//             // printAllFormats(data, "Input");
//             // printAllFormats(retval, "Output");
//             
//             return retval;
//         };
//     });
//     console.warn(`[*] hook_monitor_encrypt is injected!`);
// };
// hook_monitor_encrypt();

/*
关于 数据转换 (Data Conversion) 的详解

在逆向过程中，数据的展现形式多种多样。
最常见的二进制数据载体是 `byte[]` (Java 字节数组)。

转换的必要性：
1. 人类可读性：
   - `byte[]` 直接打印是对象地址 `[B@xxxx`，无法阅读。
   - 需要转成 Hex (十六进制) 或 Base64 以便查看内容。
   - 如果是文本内容，需要转成 String。

2. 协议分析：
   - 很多加密算法的输入输出都是 Hex 字符串。
   - 网络传输常用 Base64。

常见坑：
1. 乱码：
   - 如果 `byte[]` 包含非打印字符（如加密后的密文），强制转 String 会显示乱码，甚至丢失数据。
   - 此时应该优先看 Hex。

2. 编码问题：
   - 默认通常是 UTF-8。
   - 但有些老旧系统可能用 GBK，或者 Crypto 库可能用 ISO-8859-1。

速记：
1. 拿到 `byte[]`，先看 Hex，再试 String。
2. 看到 "0x..." 或 "A1 B2..." 是 Hex。
3. 看到 "..." 或 "==" 结尾，是 Base64。
*/
