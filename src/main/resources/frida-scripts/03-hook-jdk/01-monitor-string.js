// Monitor String operations
// 监控 String 操作（需要过滤，否则会很卡）
// java.lang.String: Java中最基础的字符串类，不可变。
// 用途：几乎涉及所有文本处理，如HTTP请求/响应(JSON/XML)、加解密前的明文/密文转换、文件路径、SQL语句拼接等。
// 逆向价值：Hook String可以监控到应用运行过程中产生的关键文本信息（Token、密钥、URL等）。
function hook_monitor_String() {
    Java.perform(function () {
        let java_lang_String = Java.use('java.lang.String');
        // 目标关键词: 请你一定要进行过滤，不需要的就去掉；
        let targetKeywords = [
            // 请求头相关
            "sign", "token", "auth", "authorization", "cookie", "session",
            "x-sign", "x-token", "user-agent", "content-type", "accept",
            "referer", "host", "connection", "accept-encoding",

            // 核心参数
            "wToken",
            "X-Argus", "X-Gorgon", "X-Helios", "X-Khronos", "X-Ladon", "X-Medusa", "X-Soter",

            // 参数相关
            "param", "data", "body", "query", "form", "json", "xml",
            "id", "uid", "userid", "username", "password", "phone", "email",
            "timestamp", "nonce", "version", "appkey", "secret",

            // 响应相关
            "code", "status", "message", "result", "data", "error", "success"
        ];

        // 辅助函数：打印调用栈
        function showJavaStacks() {
            console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        }

        // 辅助函数：检查字符串是否包含目标关键词
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

        // 监控String构造函数
        // 作用: 将字节数组(byte[])或字符数组(char[])转换为字符串。
        // 逆向场景：常用于监控解密后的数据（如AES解密后new String(bytes)）或网络响应数据。
        java_lang_String["$init"].overload('[B').implementation = function (bytes) {
            var result = this["$init"](bytes);
            let str = result.toString();
            if (containsTargetKeywords(str)) {
                console.log(`[->] java_lang_String.$init(byte[]) is called!`);
                console.log(`    ->content= ${str}`);
                showJavaStacks();
            }
            return result;
        };

        java_lang_String["$init"].overload('[C').implementation = function (chars) {
            var result = this["$init"](chars);
            let str = result.toString();
            if (containsTargetKeywords(str)) {
                console.log(`[->] java_lang_String.$init(char[]) is called!`);
                console.log(`    ->content= ${str}`);
                showJavaStacks();
            }
            return result;
        };

        java_lang_String["$init"].overload('[B', 'java.lang.String').implementation = function (bytes, charsetName) {
            var result = this["$init"](bytes, charsetName);
            let str = result.toString();
            if (containsTargetKeywords(str)) {
                console.log(`[->] java_lang_String.$init(byte[], String) is called!`);
                console.log(`    ->content= ${str}`);
                console.log(`    ->charset= ${charsetName}`);
                showJavaStacks();
            }
            return result;
        };

        // 监控concat方法
        // 作用: 字符串拼接。
        // 逆向场景：监控URL拼接、参数组合、SQL语句生成等。
        java_lang_String["concat"].implementation = function (str) {
            let result = this["concat"](str);
            let original = this.toString();
            if (containsTargetKeywords(original) || containsTargetKeywords(str)) {
                console.log(`[->] java_lang_String.concat is called!`);
                console.log(`    ->original= ${original}`);
                console.log(`    ->str= ${str}`);
                console.log(`[<-] java_lang_String.concat ended!`);
                console.log(`    retval= ${result}`);
                showJavaStacks();
            }
            return result;
        };

        // 监控replace方法
        // 作用: 字符串替换。
        // 逆向场景：监控数据清洗过程，如去除空格、替换特殊字符、URL参数处理等。
        java_lang_String["replace"].overload('java.lang.CharSequence', 'java.lang.CharSequence').implementation = function (target, replacement) {
            let result = this["replace"](target, replacement);
            let original = this.toString();
            if (containsTargetKeywords(original) || containsTargetKeywords(result) || containsTargetKeywords(target.toString()) || containsTargetKeywords(replacement.toString())) {
                console.log(`[->] java_lang_String.replace is called!`);
                console.log(`    ->original= ${original}`);
                console.log(`    ->target= ${target}`);
                console.log(`    ->replacement= ${replacement}`);
                console.log(`[<-] java_lang_String.replace ended!`);
                console.log(`    retval= ${result}`);
                showJavaStacks();
            }
            return result;
        };

        // 监控substring方法
        // 作用: 截取字符串。
        // 逆向场景：从长文本中提取关键信息（如从Response中提取Token、截取协议头等）。
        java_lang_String["substring"].overload('int').implementation = function (beginIndex) {
            let result = this["substring"](beginIndex);
            let original = this.toString();
            if (containsTargetKeywords(original)) {
                console.log(`[->] java_lang_String.substring is called!`);
                console.log(`    ->original= ${original}`);
                console.log(`    ->beginIndex= ${beginIndex}`);
                console.log(`[<-] java_lang_String.substring ended!`);
                console.log(`    retval= ${result}`);
                showJavaStacks();
            }
            return result;
        };

        // 监控format方法
        // 作用: 字符串格式化。
        // 逆向场景：监控日志输出、URL拼接、SQL拼接等格式化操作。
        java_lang_String["format"].overload('java.lang.String', '[Ljava.lang.Object;').implementation = function (format, args) {
            let result = this["format"](format, args);
            if (containsTargetKeywords(result)) {
                console.log(`[->] java_lang_String.format is called!`);
                console.log(`    ->format= ${format}`);
                console.log(`    ->result= ${result}`);
                showJavaStacks();
            }
            return result;
        };

        // 监控valueOf方法
        // 作用: 将其他类型转换为字符串。
        // 逆向场景：监控类型转换过程，如数字转字符串参与签名计算。
        java_lang_String["valueOf"].overload('java.lang.Object').implementation = function (obj) {
            let result = this["valueOf"](obj);
            if (containsTargetKeywords(result)) {
                console.log(`[->] java_lang_String.valueOf is called!`);
                console.log(`    ->obj= ${obj}`);
                console.log(`    ->result= ${result}`);
                showJavaStacks();
            }
            return result;
        };

        // 监控trim方法
        // 作用: 去除字符串首尾空格。
        // 逆向场景：数据预处理。
        java_lang_String["trim"].implementation = function () {
            let result = this["trim"]();
            let original = this.toString();
            if (containsTargetKeywords(original)) {
                console.log(`[->] java_lang_String.trim is called!`);
                console.log(`    ->original= ${original}`);
                console.log(`    ->result= ${result}`);
                showJavaStacks();
            }
            return result;
        };

        // 监控split方法
        // 作用: 字符串分割。
        // 逆向场景：解析协议格式、Token分割等。
        java_lang_String["split"].overload('java.lang.String').implementation = function (regex) {
            let result = this["split"](regex);
            let original = this.toString();
            if (containsTargetKeywords(original)) {
                console.log(`[->] java_lang_String.split is called!`);
                console.log(`    ->original= ${original}`);
                console.log(`    ->regex= ${regex}`);
                // print result array?
                showJavaStacks();
            }
            return result;
        };

        // 1. Hook 无参 getBytes() 方法
        // 作用: 将字符串转换为字节数组。
        // 逆向场景：**极高**。通常是加密前的最后一步（String -> byte[] -> Encrypt），或者是发送网络请求前的序列化。
        java_lang_String["getBytes"].overload().implementation = function () {
            let str = this.toString();
            // 过滤条件：包含关键词或者如果满足长度条件
            if (containsTargetKeywords(str) || str.length == 32) {
                console.log(`[->] java_lang_String.getBytes() is called!`);
                console.log(`    ->content= ${str}`);
                showJavaStacks();
            }
            return this["getBytes"]();
        };

        // 2. Hook 带字符集名称的 getBytes(String charsetName) 方法
        java_lang_String["getBytes"].overload('java.lang.String').implementation = function (charsetName) {
            let str = this.toString();
            // 过滤条件：包含关键词或者如果满足长度条件, 满足十六进制条件, 或者你能想到的各种条件
            if (containsTargetKeywords(str) || str.length == 32 || str.match(/^[0-9a-fA-F]+$/)) {
                console.log(`[->] java_lang_String.getBytes(String) is called!`);
                console.log(`    ->charsetName= ${charsetName}`);
                console.log(`    ->content= ${str}`);
                showJavaStacks();
            }
            return this["getBytes"](charsetName);
        };

        // 3. Hook 带 Charset 类型的 getBytes(Charset charset) 方法
        java_lang_String["getBytes"].overload('java.nio.charset.Charset').implementation = function (charset) {
            let str = this.toString();
            // 过滤条件: 这里写你的条件，我们这里用的是是否包含关键词
            if (containsTargetKeywords(str)) {
                console.log(`[->] java_lang_String.getBytes(Charset) is called!`);
                console.log(`    ->charset= ${charset ? charset.displayName() : 'null'}`);
                console.log(`    ->content= ${str}`);
                showJavaStacks();
            }
            return this["getBytes"](charset);
        };

        // 监控 equals 方法
        // 作用: 字符串比较。
        // 逆向场景：**极高**。常用于验证Token、密码、签名是否正确。
        java_lang_String["equals"].implementation = function (obj) {
            let result = this["equals"](obj);
            let str = this.toString();
            let other = (obj != null) ? obj.toString() : "null";
            if (containsTargetKeywords(str) || containsTargetKeywords(other)) {
                console.log(`[->] java_lang_String.equals is called!`);
                console.log(`    ->str= ${str}`);
                console.log(`    ->compareWith= ${other}`);
                console.log(`    ->result= ${result}`);
                showJavaStacks();
            }
            return result;
        };

        // 监控 equalsIgnoreCase 方法
        // 作用: 忽略大小写的字符串比较。
        // 逆向场景：同 equals，常用于头部字段比较等。
        java_lang_String["equalsIgnoreCase"].implementation = function (anotherString) {
            let result = this["equalsIgnoreCase"](anotherString);
            let str = this.toString();
            if (containsTargetKeywords(str) || containsTargetKeywords(anotherString)) {
                console.log(`[->] java_lang_String.equalsIgnoreCase is called!`);
                console.log(`    ->str= ${str}`);
                console.log(`    ->compareWith= ${anotherString}`);
                console.log(`    ->result= ${result}`);
                showJavaStacks();
            }
            return result;
        };

        // 监控 toCharArray 方法
        // 作用: 字符串转字符数组。
        // 逆向场景：常用于将字符串转换为数组进行逐字符处理（如加密、哈希算法）。
        java_lang_String["toCharArray"].implementation = function () {
            let result = this["toCharArray"]();
            let str = this.toString();
            if (containsTargetKeywords(str)) {
                console.log(`[->] java_lang_String.toCharArray is called!`);
                console.log(`    ->str= ${str}`);
                showJavaStacks();
            }
            return result;
        };

        // 监控 toUpperCase 方法
        // 作用: 转大写。
        // 逆向场景：常用于Hex字符串规范化、签名计算前的预处理。
        java_lang_String["toUpperCase"].overload().implementation = function () {
            let result = this["toUpperCase"]();
            let str = this.toString();
            if (containsTargetKeywords(str)) {
                console.log(`[->] java_lang_String.toUpperCase is called!`);
                console.log(`    ->str= ${str}`);
                console.log(`    ->result= ${result}`);
                showJavaStacks();
            }
            return result;
        };
    });

    console.warn(`[*] hook_monitor_String is injected!`);
};
hook_monitor_String();

/*
关于 Java String 的详解

String 是 Java 中最基础但也最特殊的引用类型。

核心特性：
1. 不可变性 (Immutable)：
   - String 对象一旦创建，其内容就不能改变。
   - 任何修改操作（如 substring, replace, +）都会创建新的 String 对象。
   - 优点：线程安全，适合作为 Map 的 Key，适合缓存 hash 值。

2. 字符串常量池 (String Pool)：
   - 为了节省内存，JVM 维护了一个字符串池。
   - 字面量赋值 String s = "abc" 会优先从池中获取。
   - new String("abc") 会强制在堆中创建新对象（但内部字符数组可能共享）。

常见相关类：

类名                可变性      线程安全        适用场景
String              不可变      安全            少量字符串操作，常量，Map Key
StringBuilder       可变        不安全          单线程大量拼接（性能最高）
StringBuffer        可变        安全            多线程大量拼接（有锁，性能略低）

逆向中的常见编码：

编码名称        字节数/字符     说明
UTF-8           1~4 byte       互联网通用标准，英文1字节，中文3字节。
GBK             2 byte         中文 Windows 默认，中文2字节。
ISO-8859-1      1 byte         单字节编码，不支持中文（强行转会乱码或丢失）。
UTF-16          2/4 byte       Java 内存中的默认编码 (char)。

速记：
1. Hook String 构造函数可以看到很多隐蔽的字符串创建过程（如解密后的字节转字符串）。
2. 所有的 + 操作符，编译器底层都会优化成 StringBuilder.append()。
3. 看到 new String(bytes, "UTF-8") 是最常见的二进制转文本操作。
4. 如果看到乱码，尝试换一种编码方式解读（GBK 或 ISO-8859-1）。
*/
