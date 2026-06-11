// 单向证书校验:  客户端校验服务端； 如果我们是中间人抓包，就是app校验抓包软件是否是服务端；
// 抓包软件中现象：能抓到, 但是看不了内容；
// 怎么校验的：一般分java层和native层；
// java层：okhttp3, 以及系统的HttpsURLConnection； 这个去网上找脚本或者lsp模块就行；
// native层：openssl, libssl, libflutter等；这个去网上找脚本即可；手动过的话得分析校验原理；

// 双向证书校验： 服务端校验客户端证书；体现在响应丢失或者响应异常； 这个需要dump证书，请看 advanced 相关；

// 1. TODO：普通sslpinning绕过； 需要学习算法助手pro的trustme++


// 2. 针对flutter的sslpinning绕过；
function hook_bypass_flutter_sslpinning() {
    var m = Process.findModuleByName("libflutter.so");
    Memory.protect(ptr(m.base), m.size, 'rwx'); // 把代码变成可写
    // 函数入口特征码，这个来源是ida静态分析关键函数，然后复制字节码；
    var pattern = "FF C3 01 D1 FD 7B 01 A9 FC 6F 02 A9 FA 67 03 A9 F8 5F 04 A9 F6 57 05 A9 F4 4F 06 A9 08 0A 80 52 48 00 00 39";
    var res = Memory.scan(m.base, m.size, pattern, {
        onMatch: function (address, size) {
            console.warn('[*] ssl_verify_result found at: ' + address.toString());
            // 绕过ssl验证，替换返回值就行
            Interceptor.attach(address, {
                onEnter: function (args) {
                    console.warn("[*] Disabling SSL validation! bypassing!"); // 可以注释掉
                },
                onLeave: function (retval) {
                    console.warn(`[*] retval: ${retval} -> 0x1`); // 可以注释掉
                    retval.replace(0x1); // 替换返回值
                }
            });
        },
        onError: function (reason) {
            console.error('[!] There was an error scanning memory in ssl');
        },
        onComplete: function () {
            console.log("Hook ssl all done!");
        }
    });
}


/*
关于 SSL Pinning (证书绑定) 的详解

原理：
App 内部硬编码了服务端的证书（或公钥哈希）。
在建立 HTTPS 连接时，App 不仅校验系统根证书，还会比对服务端证书是否与硬编码的一致。
如果不一致（比如被 Charles/Fiddler 抓包时，证书变成了代理软件的证书），App 就会断开连接。
*/
