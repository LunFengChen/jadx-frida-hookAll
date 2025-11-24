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
