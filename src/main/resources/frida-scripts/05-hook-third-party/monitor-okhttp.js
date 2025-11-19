// Monitor OkHttp operations
// 监控 OkHttp 请求

function showJavaStacks() {
    console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
}

// ========== Hook所有拦截器 ==========
Java.perform(function () {
    var Builder = Java.use('okhttp3.OkHttpClient$Builder');

    Builder.addInterceptor.implementation = function (inter) {
        console.log("实例化拦截器：");
        console.log(JSON.stringify(inter));
        showJavaStacks();
        return this.addInterceptor(inter);
    };
});

// ========== Hook addHeader ==========
function hook_request_header() {
    Java.perform(function () {
        var Builder = Java.use("okhttp3.Request$Builder");
        Builder["addHeader"].implementation = function (str, str2) {
            if (str == "X-Hiyori") { // 可以过滤特定header
                console.log(`[*] addHeader key: ${str}, val: ${str2}`);
                showJavaStacks();
            }
            var result = this["addHeader"](str, str2);
            return result;
        };
    });
    console.warn("[*] hook_request_header success");
}

// ========== Hook URL ==========
function hook_okhttp_url() {
    Java.perform(function () {
        // Hook HttpUrl.Builder 的 addQueryParameter 方法
        let HttpUrl_Builder = Java.use("okhttp3.HttpUrl$Builder");
        
        HttpUrl_Builder.addQueryParameter.implementation = function(name, value) {
            if (name === "_rnd" || name.includes("_rnd")) { // 可以过滤特定参数
                console.log("\n================= HttpUrl.Builder.addQueryParameter =================");
                console.log(`Parameter: ${name} = ${value}`);
                showJavaStacks();
            }
            return this.addQueryParameter(name, value);
        };
        
        // Hook build() 方法查看最终URL
        HttpUrl_Builder.build.implementation = function() {
            let result = this.build();
            let url = result.toString();
            if (url.includes("_rnd=")) { // 可以过滤特定URL
                console.log("\n================= HttpUrl.Builder.build =================");
                console.log(`Final URL: ${url}`);
                showJavaStacks();
            }
            return result;
        };
        
        console.log("[*] Hooked HttpUrl.Builder for _rnd parameter");
    });
}

// 执行hooks
hook_request_header();
hook_okhttp_url();
console.warn("[*] monitor_okhttp is injected");
