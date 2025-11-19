// Monitor URL and OkHttp URL operations
// 监控 URL 请求
Java.perform(function() {
    // Hook java.net.URL
    var URL = Java.use('java.net.URL');
    URL.$init.overload('java.lang.String').implementation = function (a) {
        console.log('[java.net.URL] ' + a);
        this.$init(a);
    }
    
    // Hook okhttp3 HttpUrl
    try {
        var Builder = Java.use('okhttp3.Request$Builder');
        Builder.url.overload('okhttp3.HttpUrl').implementation = function (a) {
            var res = this.url(a);
            console.log("[okhttp3.HttpUrl] result: " + res);
            return res;
        }
    } catch(e) {
        console.log("[!] okhttp3 not found: " + e.message);
    }
    
    console.warn("[*] hook_monitor_URL is injected");
});
