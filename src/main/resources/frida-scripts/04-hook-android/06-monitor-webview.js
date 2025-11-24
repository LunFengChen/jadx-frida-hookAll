// Monitor WebView operations
// 监控 WebView（开启调试权限、监控URL注入）
function showJavaStacks() {
    console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
}

function hook_webview(){
    // 开启权限
    Java.perform(function () {
        var WebView = Java.use("android.webkit.WebView");
        WebView.$init.overload('android.content.Context').implementation = function (a) {
            console.log("WebView.$init is called");
            var retval = this.$init(a);
            this.setWebContentsDebuggingEnabled(true);
            return retval;
        }
        WebView.$init.overload('android.content.Context','android.util.AttributeSet').implementation = function (a,b) {
            console.log("WebView.$init is called");
            var retval = this.$init(a,b);
            this.setWebContentsDebuggingEnabled(true);
            return retval;
        }
        WebView.$init.overload('android.content.Context','android.util.AttributeSet','int').implementation = function (a,b,c) {
            console.log("WebView.$init is called");
            var retval = this.$init(a,b,c);
            this.setWebContentsDebuggingEnabled(true);
            return retval;
        }
        WebView.$init.overload('android.content.Context','android.util.AttributeSet','int','boolean').implementation = function (a,b,c,d) {
            console.log("WebView.$init is called");
            var retval = this.$init(a,b,c,d);
            this.setWebContentsDebuggingEnabled(true);
            return retval;
        }
        WebView.$init.overload('android.content.Context','android.util.AttributeSet','int','int').implementation = function (a,b,c,d) {
            console.log("WebView.$init is called");
            var retval = this.$init(a,b,c,d);
            this.setWebContentsDebuggingEnabled(true);
            return retval;
        }
        
        // 检查 WebView 类是否存在
        if (WebView) {
            // 重写 setWebContentsDebuggingEnabled 方法
            WebView.setWebContentsDebuggingEnabled.implementation = function (enabled) {
                this.setWebContentsDebuggingEnabled(true);
                console.log("setWebContentsDebuggingEnabled is called with argument: " + enabled);
            };
        } else {
            console.log("WebView class not found");
        }
    });

    // 监控url注入
    Java.perform(function (){
        let WebView = Java.use("android.webkit.WebView");
        WebView["postUrl"].implementation = function (str, bArr) {
            var string = Java.use('java.lang.String').$new(bArr);
            console.log(`[*] WebView.postUrl is called: str=${str}, string=${string}`);
            this["postUrl"](str, bArr);
        };
        WebView["loadUrl"].overload('java.lang.String').implementation = function (str) {
            console.log(`[*] WebView.loadUrl-1 is called: str=${str}`);
            var s = Java.use('java.lang.String').$new(str);
            var t = Java.use('java.lang.String').$new("https");
            if (s.contains(t)) {// 用java的api进行过滤
                showJavaStacks();
            }
            this["loadUrl"](str);
        };
        WebView["loadUrl"].overload('java.lang.String', 'java.util.Map').implementation = function (str, map) {
            console.log(`[*] WebView.loadUrl-2 is called: str=${str}, map=${map}`);
            this["loadUrl"](str, map);
        };
    });
    
    console.warn("[*] hook_webview is injected");
}

hook_webview();

/*
关于 WebView (网页视图) 的详解

WebView 是 Android 内嵌的浏览器组件，用于显示 Web 页面。
现在的 App 越来越多是 Hybrid (混合) 架构，关键业务逻辑（如加密、签名、风控验证）可能都在 JS 里。

逆向价值：
1. 开启调试 (Debugging)：
   - 脚本自动调用 `setWebContentsDebuggingEnabled(true)`。
   - 这样你就可以用 Chrome 浏览器 -> `chrome://inspect` -> `App Webview` 来调试 App 内的 H5 页面。
   - 可以查看 Console 日志、打 JS 断点、查看 Network 请求。

2. URL 监控：
   - 监控 `loadUrl` 可以知道 App 加载了哪些网页。
   - 有时候 Token 是通过 URL 参数传递给 H5 的，Hook 这里能直接抓到。

3. JS 注入 (postUrl)：
   - 监控 App 如何向网页提交数据。

速记：
1. 只要是 H5 页面，第一步先 Hook 这个脚本开启调试模式。
2. 如果是纯 H5 逻辑，直接用 Chrome 调试，比 Hook Java 爽多了。
*/
