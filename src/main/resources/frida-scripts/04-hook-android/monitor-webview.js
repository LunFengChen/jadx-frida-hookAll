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
