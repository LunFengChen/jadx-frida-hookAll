// Dump SSL certificate from KeyStore
// Java层证书自吐
function hook_cert() {
    // 获取安全路径（兼容Android 10+）
    function getSafePath() {
        try {
            const Environment = Java.use("android.os.Environment");
            
            // 优先使用应用私有目录（无需权限）
            try {
                const ctx = Java.use("android.app.ActivityThread").currentApplication();
                return ctx.getExternalFilesDir("Download").getAbsolutePath();
            } catch (e) {
                // 回退到公共下载目录
                return Environment.getExternalStoragePublicDirectory(
                    Environment.DIRECTORY_DOWNLOADS
                ).getAbsolutePath();
            }
        } catch (e) {
            // 终极回退路径
            return "/sdcard/Download";
        }
    }

    function write_cert(inputStream, filename) {
        try {
            const safePath = getSafePath();
            const fullPath = `${safePath}/${filename}`;
            
            const File = Java.use("java.io.File");
            const FileOutputStream = Java.use("java.io.FileOutputStream");
            
            const file = File.$new(fullPath);
            const out = FileOutputStream.$new(file);
            
            // 完全正确的读取方法 - 使用三个参数的重载
            const buffer = Java.array('byte', Array(4096).fill(0));
            let totalBytes = 0;
            
            let read;
            while (true) {
                try {
                    // 使用三个参数的重载: read(byte[] b, int off, int len)
                    read = inputStream.read.overload('[B', 'int', 'int').call(
                        inputStream, buffer, 0, buffer.length
                    );
                    
                    if (read === -1) break;
                    
                    out.write(buffer, 0, read);
                    totalBytes += read;
                } catch (e) {
                    console.error(`[-] 读取过程中出错: ${e}`);
                    break;
                }
            }
            
            out.flush();
            out.close();
            console.warn(`[+] 证书保存成功! 大小: ${totalBytes}字节, 路径: ${fullPath}`);
            return fullPath;
        } catch (e) {
            console.error(`[-] 证书保存失败: ${e}`);
            return null;
        }
    }

    Java.perform(function () {
        const KeyStore = Java.use("java.security.KeyStore");
        
        KeyStore.load.overload('java.io.InputStream', '[C').implementation = function (inputStream, pwd) {
            // 1. 处理null输入流的情况
            if (inputStream === null) {
                console.warn("[!] 输入流为null，跳过证书导出");
                return this.load(inputStream, pwd);
            }
            
            // 2. 先获取证书类型
            const certType = this.getType().toLowerCase();
            
            // 3. 复制输入流（解决单次读取问题）
            const ByteArrayOutputStream = Java.use("java.io.ByteArrayOutputStream");
            const bos = ByteArrayOutputStream.$new();
            
            // 使用三个参数的重载进行读取
            const buffer = Java.array('byte', Array(4096).fill(0));
            
            try {
                let bytesRead;
                while (true) {
                    // 使用三个参数的重载: read(byte[] b, int off, int len)
                    bytesRead = inputStream.read.overload('[B', 'int', 'int').call(
                        inputStream, buffer, 0, buffer.length
                    );
                    
                    if (bytesRead === -1) break;
                    
                    bos.write(buffer, 0, bytesRead);
                }
                bos.flush();
            } catch (e) {
                console.error(`[-] 流读取错误: ${e}`);
                return this.load(inputStream, pwd);
            }
            
            const certData = bos.toByteArray();
            const origStream = Java.use("java.io.ByteArrayInputStream").$new(certData);
            const copyStream = Java.use("java.io.ByteArrayInputStream").$new(certData);
            
            // 4. 保存证书文件
            const extensions = {
                "pkcs12": ".p12",
                "bks": ".bks",
                "jks": ".jks",
                "jceks": ".jceks",
                "uber": ".ubr"
            };
            
            const ext = extensions[certType] || ".cer";
            const filename = `cert_${Date.now()}${ext}`;
            const savedPath = write_cert(copyStream, filename);
            
            // 5. 打印关键信息
            console.log("\n=================================");
            console.log(`[*] 证书类型: ${certType}`);
            console.log(`[*] 证书密码: ${Java.use("java.lang.String").$new(pwd)}`);
            if (savedPath) console.log(`[*] 存储路径: ${savedPath}`);
            
            // 6. 打印堆栈（定位证书来源）
            try {
                console.log(Java.use("android.util.Log").getStackTraceString(
                    Java.use("java.lang.Throwable").$new()
                ));
            } catch (e) {
                console.log(`[-] 堆栈打印失败: ${e}`);
            }
            
            // 7. 用原始流继续执行加载操作
            return this.load(origStream, pwd);
        };
    });
}

setImmediate(hook_cert);
