// Monitor Java Cryptography Architecture (JCA) operations
// 监控 Java 加密架构 (MessageDigest, Mac, Cipher, Signature)
// 用途：监控所有哈希计算(MD5/SHA)、HMAC签名、AES/RSA加解密。
// 逆向价值：**最高**。这是定位签名算法、获取加密密钥(Key/IV)的最直接路径。
function hook_monitor_crypto() {
    Java.perform(function () {
        // Helper: Print Stack Trace
        function showJavaStacks() {
            if (global.fridaHelperConfig && global.fridaHelperConfig.printStack === false) return;
            console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        }

        // Helper: Byte Array to Hex
        function bytesToHex(bytes) {
            if (!bytes) return "null";
            let hex = "";
            for (let i = 0; i < bytes.length; i++) {
                let b = bytes[i] & 0xff;
                if (b < 16) hex += "0";
                hex += b.toString(16);
            }
            return hex;
        }

        // Helper: Byte Array to String
        function bytesToString(bytes) {
            if (!bytes) return "null";
            try {
                let str = Java.use("java.lang.String").$new(bytes, "UTF-8");
                // 简单过滤非打印字符
                if (/^[\x20-\x7E]*$/.test(str)) return str;
                return "[binary]";
            } catch (e) {
                return "[error]";
            }
        }

        // ========================================================================
        // 1. MessageDigest (Hash: MD5, SHA-1, SHA-256)
        // ========================================================================
        let MessageDigest = Java.use("java.security.MessageDigest");
        
        // 监控 update (输入数据)
        MessageDigest["update"].overload('[B').implementation = function (input) {
            console.log(`\n[->] MessageDigest.update(byte[]) algo=${this.getAlgorithm()}`);
            console.log(`    ->input(hex)= ${bytesToHex(input)}`);
            console.log(`    ->input(str)= ${bytesToString(input)}`);
            // showJavaStacks();
            return this["update"](input);
        };

        // 监控 digest (输出结果)
        MessageDigest["digest"].overload().implementation = function () {
            let result = this["digest"]();
            console.log(`\n[<-] MessageDigest.digest() algo=${this.getAlgorithm()}`);
            console.log(`    ->result(hex)= ${bytesToHex(result)}`);
            showJavaStacks();
            return result;
        };
        
        // 监控 digest(byte[]) (一次性输入并输出)
        MessageDigest["digest"].overload('[B').implementation = function (input) {
            console.log(`\n[->] MessageDigest.digest(byte[]) algo=${this.getAlgorithm()}`);
            console.log(`    ->input(hex)= ${bytesToHex(input)}`);
            console.log(`    ->input(str)= ${bytesToString(input)}`);
            let result = this["digest"](input);
            console.log(`    ->result(hex)= ${bytesToHex(result)}`);
            showJavaStacks();
            return result;
        };

        // ========================================================================
        // 2. Mac (HMAC)
        // ========================================================================
        let Mac = Java.use("javax.crypto.Mac");
        
        // 监控 init (Key)
        Mac["init"].overload('java.security.Key').implementation = function (key) {
            console.log(`\n[->] Mac.init() algo=${this.getAlgorithm()}`);
            console.log(`    ->key_algo= ${key.getAlgorithm()}`);
            console.log(`    ->key_bytes(hex)= ${bytesToHex(key.getEncoded())}`);
            showJavaStacks();
            return this["init"](key);
        };

        // 监控 update
        Mac["update"].overload('[B').implementation = function (input) {
            // console.log(`[->] Mac.update()`); // 有时候 update 太多，可以注释掉
            return this["update"](input);
        };

        // 监控 doFinal
        Mac["doFinal"].overload().implementation = function () {
            let result = this["doFinal"]();
            console.log(`\n[<-] Mac.doFinal() algo=${this.getAlgorithm()}`);
            console.log(`    ->result(hex)= ${bytesToHex(result)}`);
            showJavaStacks();
            return result;
        };
        
        Mac["doFinal"].overload('[B').implementation = function (input) {
            let result = this["doFinal"](input);
            console.log(`\n[<-] Mac.doFinal(byte[]) algo=${this.getAlgorithm()}`);
            console.log(`    ->input(hex)= ${bytesToHex(input)}`);
            console.log(`    ->input(str)= ${bytesToString(input)}`);
            console.log(`    ->result(hex)= ${bytesToHex(result)}`);
            showJavaStacks();
            return result;
        };

        // ========================================================================
        // 3. Cipher (Encryption/Decryption: AES, DES, RSA)
        // ========================================================================
        let Cipher = Java.use("javax.crypto.Cipher");
        
        // 监控 init (Key, IV)
        // 重载较多，这里只监控最常用的
        Cipher["init"].overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = function (mode, key, params) {
            let modeStr = (mode === 1) ? "ENCRYPT_MODE" : (mode === 2 ? "DECRYPT_MODE" : mode);
            console.log(`\n[->] Cipher.init() algo=${this.getAlgorithm()} mode=${modeStr}`);
            console.log(`    ->key_bytes(hex)= ${bytesToHex(key.getEncoded())}`);
            // 尝试解析 IV (通常 params 是 IvParameterSpec)
            try {
                let IvParameterSpec = Java.use("javax.crypto.spec.IvParameterSpec");
                let ivSpec = Java.cast(params, IvParameterSpec);
                console.log(`    ->iv_bytes(hex)= ${bytesToHex(ivSpec.getIV())}`);
            } catch (e) {
                console.log(`    ->params= ${params.toString()}`);
            }
            showJavaStacks();
            return this["init"](mode, key, params);
        };
        
        // 监控 doFinal (加解密结果)
        Cipher["doFinal"].overload('[B').implementation = function (input) {
            let result = this["doFinal"](input);
            console.log(`\n[<-] Cipher.doFinal() algo=${this.getAlgorithm()}`);
            console.log(`    ->input(hex)= ${bytesToHex(input)}`);
            console.log(`    ->input(str)= ${bytesToString(input)}`);
            console.log(`    ->result(hex)= ${bytesToHex(result)}`);
            // showJavaStacks();
            return result;
        };

        // ========================================================================
        // 4. Signature (RSA/DSA Sign)
        // ========================================================================
        let Signature = Java.use("java.security.Signature");
        
        Signature["sign"].overload().implementation = function () {
            let result = this["sign"]();
            console.log(`\n[<-] Signature.sign() algo=${this.getAlgorithm()}`);
            console.log(`    ->signature(hex)= ${bytesToHex(result)}`);
            showJavaStacks();
            return result;
        };
        
        Signature["verify"].overload('[B').implementation = function (signature) {
            let result = this["verify"](signature);
            console.log(`\n[<-] Signature.verify() algo=${this.getAlgorithm()}`);
            console.log(`    ->signature(hex)= ${bytesToHex(signature)}`);
            console.log(`    ->result= ${result}`);
            showJavaStacks();
            return result;
        };

    });
    console.warn(`[*] hook_monitor_crypto is injected!`);
}
hook_monitor_crypto();

/*
关于 Java 加密架构 (JCA) 的详解

Java 提供了一套统一的加密接口，位于 `java.security` 和 `javax.crypto` 包中。
无论底层是用 OpenSSL 还是其他库实现，上层 API 几乎都是一样的。

核心类与逆向价值：

1. MessageDigest (摘要/哈希):
   - 算法：MD5, SHA-1, SHA-256, SHA-512。
   - 特征：不可逆，通常用于签名生成、密码存储。
   - Hook点：`update(input)` 看原文，`digest()` 看结果。

2. Mac (消息认证码):
   - 算法：HmacSHA1, HmacSHA256。
   - 特征：带密钥的哈希。
   - Hook点：`init(key)` 拿密钥！`doFinal(input)` 看原文和签名。

3. Cipher (加解密):
   - 算法：AES, DES, RSA。
   - 特征：可逆。
   - Hook点：
     - `init(mode, key, iv)`: 拿密钥 (Key) 和 偏移量 (IV)！这是破解加密最关键的一步。
     - `doFinal(input)`: 看加密前的明文或解密后的明文。

4. Signature (数字签名):
   - 算法：SHA256withRSA, MD5withRSA。
   - 特征：非对称加密，私钥签名，公钥验签。
   - Hook点：`sign()`。

速记：
1. 只要是标准的 Java 加密，Hook 这几个类绝对能抓到。
2. `Cipher.init` 是获取 AES Key/IV 的神器。
3. 看到乱码？那是加密后的 bytes。看到 hex 字符串？那是转 hex 后的结果。
*/
