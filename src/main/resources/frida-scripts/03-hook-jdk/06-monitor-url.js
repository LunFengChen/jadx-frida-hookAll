// Monitor URL operations
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
    });
    console.warn(`[*] hook_monitor_URL is injected!`);
};
hook_monitor_URL();

/*
关于 URL (Uniform Resource Locator) 的详解

URL 类是 Java 中用于表示网络资源的标准类。虽然现代 Android 开发多使用 OkHttp/Retrofit，但在某些场景下 URL 依然很重要。

核心作用：
- 解析 URL 字符串 (协议、主机、端口、路径、参数)。
- 打开网络连接 (openConnection)。

逆向价值：
1. 发现 API 端点：很多第三方 SDK (如广告、统计、支付) 内部为了不依赖 OkHttp，会直接用 URL 类发起请求。
2. 资源下载：监控图片、插件、配置文件的下载地址。
3. 协议分析：查看使用的协议是 HTTP 还是 HTTPS，是否有非标端口。

速记：
1. 如果 Hook OkHttp 没抓到包，试试 Hook URL 构造函数。
2. 看到 "http://" 或 "https://" 开头的字符串，多半就是传给 URL 的。
*/
