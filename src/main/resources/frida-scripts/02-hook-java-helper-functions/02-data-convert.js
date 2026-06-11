// 功能：常用数据格式互转 - 字节数组、十六进制、字符串、Base64 互转

// ==================== 字节数组 <-> 十六进制 ====================

// 方式 1: 简洁版 (推荐)
function bytesToHex(bytes) {
    var hex = '';
    for (var i = 0; i < bytes.length; i++) {
        hex += ('0' + (bytes[i] & 0xFF).toString(16)).slice(-2);
    }
    return hex;
}

// 方式 2: 兼容负数的版本 (适用于某些特殊场景)
function bytesToHex_Compatible(bytes) {
    let str = '';
    for (let i = 0; i < bytes.length; i++) {
        let k = bytes[i];
        let j = k;
        if (k < 0) j = k + 256;  // 处理负数
        if (j < 16) str += "0";
        str += j.toString(16);
    }
    return str;
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

// 方式 1: 使用 Java API (推荐)
function bytesToString(bArr) {
    var JDKClass_String = Java.use('java.lang.String');
    return JDKClass_String.$new(Java.array('byte', bArr)).toString();
}

// 方式 2: 纯 JavaScript 实现 (不依赖 Java)
function bytesToString_JS(bytes) {
    let str = '';
    bytes = new Uint8Array(bytes);
    for (var i = 0; i < bytes.length; i++) {
        str += String.fromCharCode(bytes[i]);
    }
    return str;
}

// 字节数组转 UTF-8 字符串 (使用 Charset)
function bytesToUtf8(exampleBytes) {
    var JDKClass_String = Java.use("java.lang.String");
    var JDKClass_Charset = Java.use("java.nio.charset.Charset");
    var utf8Charset = JDKClass_Charset.forName("UTF-8");
    return JDKClass_String.$new(exampleBytes, utf8Charset);
}

// 利用android的API将字节数组转为字符串
function bytesToByteString(exampleBytes) {
    let AndroidClass_ByteString = Java.use("com.android.okhttp.okio.ByteString");
    // 这里如果没有overload容易报错
    let value_str = AndroidClass_ByteString.of.overload('[B').call(AndroidClass_ByteString, exampleBytes).utf8();
    return value_str;
}

// 字符串转字节数组
function stringToBytes(str) {
    var JDKClass_String = Java.use("java.lang.String");
    return JDKClass_String.$new(str).getBytes();
}

// ==================== 字节数组 <-> Base64 ====================

// 方式 1: 使用 Android API (推荐，简洁)
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

// 方式 2: 纯 JavaScript 实现 (不依赖 Java)
const base64EncodeChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const base64DecodeChars = [-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,-1,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,-1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1];

// 纯 JS 实现：字节数组转 Base64
function bytesToBase64_JS(bytes) {
    var result = '';
    var length = bytes.length;
    var i = 0;
    
    // 每次处理 3 个字节，转换为 4 个 Base64 字符
    while (i < length) {
        var byte1 = bytes[i++] & 0xFF;
        var byte2 = i < length ? bytes[i++] & 0xFF : 0;
        var byte3 = i < length ? bytes[i++] & 0xFF : 0;
        
        // 将 3 个字节（24位）分成 4 组，每组 6 位
        var enc1 = byte1 >> 2;
        var enc2 = ((byte1 & 0x03) << 4) | (byte2 >> 4);
        var enc3 = ((byte2 & 0x0F) << 2) | (byte3 >> 6);
        var enc4 = byte3 & 0x3F;
        
        result += base64EncodeChars.charAt(enc1);
        result += base64EncodeChars.charAt(enc2);
        result += (i - 1 < length) ? base64EncodeChars.charAt(enc3) : '=';
        result += (i < length) ? base64EncodeChars.charAt(enc4) : '=';
    }
    
    return result;
}

// 纯 JS 实现：字符串转 Base64
function stringToBase64_JS(str) {
    var result = '';
    var length = str.length;
    var i = 0;
    
    while (i < length) {
        var char1 = str.charCodeAt(i++) & 0xFF;
        var char2 = i < length ? str.charCodeAt(i++) & 0xFF : 0;
        var char3 = i < length ? str.charCodeAt(i++) & 0xFF : 0;
        
        var enc1 = char1 >> 2;
        var enc2 = ((char1 & 0x03) << 4) | (char2 >> 4);
        var enc3 = ((char2 & 0x0F) << 2) | (char3 >> 6);
        var enc4 = char3 & 0x3F;
        
        result += base64EncodeChars.charAt(enc1);
        result += base64EncodeChars.charAt(enc2);
        result += (i - 1 < length) ? base64EncodeChars.charAt(enc3) : '=';
        result += (i < length) ? base64EncodeChars.charAt(enc4) : '=';
    }
    
    return result;
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

// js数组转java的字节数组
function bytesToUtf8_Cast(objArr) {
    var JDKClass_Byte = Java.use("[B");
    var buffer = Java.cast(objArr[0], JDKClass_Byte);
    var res = Java.array('byte', buffer);
    return res;
}

// ==================== 辅助函数 ====================

// 打印所有格式的数据
function printAllFormats(bytes, dataName) {
    console.log(dataName + " in all formats:");
    console.log("  Hex:    " + bytesToHex(bytes));
    console.log("  String: " + bytesToString(bytes));
    console.log("  Base64: " + bytesToBase64(bytes));
}



/*
关于 数据转换 (Data Conversion) 的详解

在逆向过程中，数据的展现形式多种多样。
最常见的二进制数据载体是 `byte[]` (Java 字节数组)或者说是 `bytes` (py等语言中的字节序列).

转换的必要性：
1. 人类可读性：
   - `byte[]` 直接打印是Java对象地址 `[B@xxxx`，无法阅读。
   - 需要转成 Hex (十六进制) 或 Base64 以便查看内容。
   - 如果是文本内容，需要转成 String。

2. 协议分析：
   - 很多加密算法的输入输出都是 Hex 字符串。
   - 网络传输常用 Base64。

常见坑：
1. 乱码：
   - 如果 `byte[]` 包含非打印字符（如加密后的密文），强制转 String 会显示乱码，甚至丢失数据。
   - 此时应该看 Hex。

2. 编码问题：
   - 默认通常是 UTF-8, 脚本也只关注这个编码。
   - 但有些老旧系统可能用 GBK，或者 Crypto 库可能用 ISO-8859-1。

*/
