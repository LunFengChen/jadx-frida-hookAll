// Monitor Activity operations (page switching)
// 监测页面切换
function showJavaStacks() {
    const LogClass = Java.use("android.util.Log");
    console.log(LogClass.getStackTraceString(Java.use("java.lang.Exception").$new()));
}

function hook_monitor_activity() {
    Java.perform(function () {
        var Activity = Java.use("android.app.Activity");
        
        Activity.startActivity.overload('android.content.Intent').implementation = function (p1) {
            console.log("[*] Hooking android.app.Activity.startActivity(p1) successfully\n\tp1=" + p1);
            showJavaStacks();
            console.log(decodeURIComponent(p1.toUri(256)));
            this.startActivity(p1);
        }
        
        Activity.startActivity.overload('android.content.Intent', 'android.os.Bundle').implementation = function (p1, p2) {
            console.log("[*] android.app.Activity.startActivity(p1,p2) successfully\n\tp1=" + p1 + "\n\tp2=" + p2);
            showJavaStacks();
            console.log(decodeURIComponent(p1.toUri(256)));
            this.startActivity(p1, p2);
        }
        
        Activity.startService.overload('android.content.Intent').implementation = function (p1) {
            console.log("[*] android.app.Activity.startService(p1) successfully\n\tp1=" + p1);
            showJavaStacks();
            console.log(decodeURIComponent(p1.toUri(256)));
            this.startService(p1);
        }
    })
    console.warn(`[*] hook_monitor_activity is injected !`);
}

hook_monitor_activity();

/*
关于 Activity 跳转 (StartActivity) 的详解

Activity 是 Android 应用中最基本的页面组件。
`startActivity(Intent)` 是页面跳转的标准方法。

Intent (意图)：
Intent 携带了跳转的目标组件信息和传递的参数 (Extras/Bundle)。

逆向价值：
1. 梳理页面流程：
   - 通过监控 startActivity，可以画出 App 的页面跳转图。
   - 知道点击某个按钮后跳转到了哪个 Activity 类。

2. 参数拦截：
   - 很多 App 会通过 Intent 传递关键参数（如 user_id, order_id, webview_url）。
   - 尤其是 Web 跳转 (Scheme/DeepLink)，Intent 的 Data URI 往往包含了解密后的参数。

3. 动态调试：
   - 知道了 Activity 类名，就可以去 Jadx 里搜索该类，分析其 `onCreate` 或 `onResume` 方法。

速记：
1. 看到 `Intent { act=... dat=... cmp=... }`，重点关注 `cmp` (目标类名) 和 `extras` (参数)。
2. 如果是插件化或热更新的 App，目标 Activity 可能是个 Stub (桩)，真正的业务逻辑可能在 Fragment 里。
*/
