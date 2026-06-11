// Dump SSL certificate from KeyStore
// Java层证书自吐
function hook_cert() {
    // 简化版：直接使用 Java 流复制工具
    function saveCert(data, filename) {
        try {
            const path = `/sdcard/Download/${filename}`;
            const FileOutputStream = Java.use("java.io.FileOutputStream");
            const fos = FileOutputStream.$new(path);
            fos.write(data);
            fos.close();
            console.warn(`[+] 证书已保存: ${path} (${data.length} 字节)`);
            return path;
        } catch (e) {
            console.error(`[-] 保存失败: ${e}`);
            return null;
        }
    }
    
    // 读取输入流到字节数组
    function readStream(inputStream) {
        const ByteArrayOutputStream = Java.use("java.io.ByteArrayOutputStream");
        const baos = ByteArrayOutputStream.$new();
        const buffer = Java.array('byte', Array(8192).fill(0));
        let len;
        while ((len = inputStream.read(buffer)) !== -1) {
            baos.write(buffer, 0, len);
        }
        return baos.toByteArray();
    }

    Java.perform(function () {
        const KeyStore = Java.use("java.security.KeyStore");
        
        KeyStore.load.overload('java.io.InputStream', '[C').implementation = function (inputStream, pwd) {
            if (inputStream === null) {
                return this.load(inputStream, pwd);
            }
            
            try {
                // 获取证书类型和密码
                const certType = this.getType().toLowerCase();
                const password = pwd ? Java.use("java.lang.String").$new(pwd) : "null";
                
                // 读取证书数据
                const certData = readStream(inputStream);
                
                // 保存证书
                const extMap = {"pkcs12": ".p12", "bks": ".bks", "jks": ".jks", "jceks": ".jceks"};
                const ext = extMap[certType] || ".cer";
                const filename = `cert_${Date.now()}${ext}`;
                saveCert(certData, filename);
                
                // 打印信息
                console.log(`\n[*] 证书类型: ${certType}`);
                console.log(`[*] 证书密码: ${password}`);
                
                // 用新流继续加载
                const ByteArrayInputStream = Java.use("java.io.ByteArrayInputStream");
                return this.load(ByteArrayInputStream.$new(certData), pwd);
                
            } catch (e) {
                console.error(`[-] Hook失败: ${e}`);
                return this.load(inputStream, pwd);
            }
        };
    });
}
hook_cert();
