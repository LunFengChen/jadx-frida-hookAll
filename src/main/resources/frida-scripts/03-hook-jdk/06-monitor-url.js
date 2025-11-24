// Monitor URL and OkHttp URL operations
// 监控 URL 请求
// java.net.URL: 标准Java URL类。
// 用途：表示统一资源定位符。
// 逆向价值：**高**。尽管现代App多用OkHttp/Retrofit，但底层或某些SDK仍可能使用URL。Hook构造函数可以发现API端点。
function hook_monitor_URL() {
    Java.perform(function () {
        // Hook java.net.URL
        let java_net_URL = Java.use('java.net.URL');
        java_net_URL["$init"].overload('java.lang.String').implementation = function (a) {
            console.log(`[->] java_net_URL.$init is called! args are as follows:\n    ->a= ${a}`);
            var retval = this["$init"](a);
            console.log(`[<-] java_net_URL.$init ended!`);
            return retval;
        };

        // Hook okhttp3 HttpUrl
        // okhttp3.HttpUrl: OkHttp库的URL类。
        // 逆向价值：**极高**。绝大多数Android应用使用OkHttp/Retrofit。Hook这个类的parse/url方法能捕获所有HTTP请求的URL。
        try {
            let okhttp3_Request_Builder = Java.use('okhttp3.Request$Builder');
            okhttp3_Request_Builder["url"].overload('okhttp3.HttpUrl').implementation = function (a) {
                console.log(`[->] okhttp3_Request_Builder.url is called! args are as follows:\n    ->a= ${a}`);
                var retval = this["url"](a);
                console.log(`[<-] okhttp3_Request_Builder.url ended! \n    retval= ${retval}`);
                return retval;
            };
            
            // 增加对 url(String) 的监控，防止漏网之鱼
            okhttp3_Request_Builder["url"].overload('java.lang.String').implementation = function (a) {
                console.log(`[->] okhttp3_Request_Builder.url(String) is called! args are as follows:\n    ->a= ${a}`);
                var retval = this["url"](a);
                console.log(`[<-] okhttp3_Request_Builder.url ended!`);
                return retval;
            };

        } catch (e) {
            console.log("[!] okhttp3 not found: " + e.message);
        }
    });
    console.warn(`[*] hook_monitor_URL is injected!`);
};
hook_monitor_URL();
