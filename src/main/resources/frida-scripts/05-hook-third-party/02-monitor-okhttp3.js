// Monitor OkHttp3 requests and responses
// 监控 OkHttp3 网络请求
// 核心逻辑：Hook RealCall 的 getResponseWithInterceptorChain 方法，或者动态添加 Interceptor。

function hook_monitor_okhttp3() {
    Java.perform(function () {
        // 辅助函数：查找 OkHttp3 的核心类
        // 因为混淆的存在，直接 use("okhttp3.OkHttpClient") 可能会失败。
        // 这里尝试几种常见的类名。
        
        let OkHttpClient = null;
        let RealCall = null;
        
        try { OkHttpClient = Java.use("okhttp3.OkHttpClient"); } catch(e) {}
        try { RealCall = Java.use("okhttp3.RealCall"); } catch(e) {}
        
        if (!OkHttpClient || !RealCall) {
            console.error("[-] OkHttp3 classes not found. App might be obfuscated or not using OkHttp3.");
            return;
        }

        // 动态创建一个 Interceptor 类
        // 这是一个非常强大的技巧：用 Frida 在运行时定义一个实现了 Java 接口的新类。
        const Interceptor = Java.use("okhttp3.Interceptor");
        const MyInterceptor = Java.registerClass({
            name: "com.frida.OkHttpLogger", // 自定义类名
            implements: [Interceptor],
            methods: {
                intercept: function (chain) {
                    let request = chain.request();
                    
                    // --- 打印请求 ---
                    console.log(`\n[+] Request: ${request.method()} ${request.url()}`);
                    
                    // 打印 Headers
                    let headers = request.headers();
                    console.log(`[+] Request Headers:\n${headers}`);
                    
                    // 打印 Body (如果有)
                    let requestBody = request.body();
                    if (requestBody) {
                        try {
                            let Buffer = Java.use("okio.Buffer");
                            let buffer = Buffer.$new();
                            requestBody.writeTo(buffer);
                            let charset = Java.use("java.nio.charset.Charset").forName("UTF-8");
                            // 尝试读取文本
                            console.log(`[+] Request Body:\n${buffer.readString(charset)}`);
                        } catch (e) {
                            console.log(`[+] Request Body (Binary or Error): ${e.message}`);
                        }
                    }

                    // --- 执行请求 ---
                    let response = chain.proceed(request);
                    
                    // --- 打印响应 ---
                    console.log(`\n[+] Response: ${response.code()} ${response.message()} ${request.url()}`);
                    
                    // 打印 Headers
                    // console.log(`[+] Response Headers:\n${response.headers()}`); // 响应头通常比较多，视情况开启

                    // 打印 Body (难点：不能直接 consume body，否则 App 会读不到)
                    // 正确做法是 peekBody 或者 clone source，但这比较复杂且依赖具体 okio 版本。
                    // 简单做法是只打印非流式的部分，或者这里暂时不打印 Response Body 以免崩溃。
                    // 如果必须打印，可以使用 response.peekBody(1024 * 1024).string() (OkHttp 3.5+)
                    try {
                        // 检查是否是文本类型
                        let contentType = response.header("Content-Type");
                        if (contentType && (contentType.includes("text") || contentType.includes("json") || contentType.includes("xml"))) {
                             // 限制读取 512KB，防止大文件
                             let responseBody = response.peekBody(512 * 1024);
                             console.log(`[+] Response Body (Peek):\n${responseBody.string()}`);
                        } else {
                             console.log(`[+] Response Body: [Binary or non-text data]`);
                        }
                    } catch (e) {
                        console.log(`[-] Failed to peek response body: ${e.message}`);
                    }
                    
                    return response;
                }
            }
        });

        // 将我们的 Interceptor 注入到 OkHttpClient
        // Hook Builder 的 build 方法
        const Builder = Java.use("okhttp3.OkHttpClient$Builder");
        Builder.build.implementation = function () {
            console.log("[*] OkHttpClient$Builder.build() called. Injecting Logger Interceptor...");
            
            // 添加到 interceptors 列表 (应用拦截器)
            this.interceptors().add(MyInterceptor.$new());
            
            return this.build();
        };

        console.warn("[*] Hook OkHttp3 successfully. Logger injected into new OkHttpClient instances.");
    });
}

hook_monitor_okhttp3();

// 下面代码来自季冬公众号
function hook_http(){
    Java.perform(() => {
        var ins_okhttp = Java.use("okhttp3.OkHttpClient")        
        ins_okhttp.newCall.overload('okhttp3.Request').implementation = function(a) {
            console.log(a);           
            return this.newCall(a);        
        }
        var ins_RealCall = Java.use("okhttp3.RealCall");        
        ins_RealCall.execute.overload().implementation = function() {           
            var ret = this.execute();           
            console.log(ret.toString())           
            return ret        
        }    
    })
}

/*
关于 OkHttp3 抓包的详解

原理：
OkHttp3 使用“拦截器责任链”模式。
我们动态注册一个 `okhttp3.Interceptor` 实现类，并在 `OkHttpClient.Builder.build()` 时将其添加到拦截器列表中。

优势：
1. **无需代理**：直接在 App 内部打印数据，绕过 VPN 检测。
2. **解密后数据**：如果 App 在 NetworkInterceptor 层做了加密，我们作为 ApplicationInterceptor (addInterceptor) 可以拿到加密前的明文请求和解密后的明文响应！
3. **详细日志**：比 Logcat 里的 `HttpLoggingInterceptor` 更灵活，我们可以定制输出格式。

局限：
- 只能监控脚本注入后新创建的 `OkHttpClient` 实例。如果 App 在启动时就已经创建了单例 Client，可能需要重启 App 或寻找其他 Hook 点 (如 RealCall)。
- 对于高度混淆的 App，需要先定位 `okhttp3` 包的混淆名。
*/
