// Block app crash/exit
// App闪退定位 - 拦截退出调用
function showJavaStacks() {
    console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
}

function hook_monitor_crash(){
    Java.perform(function () {
        // 拦截 System.exit()
        var System = Java.use('java.lang.System');
        System.exit.overload('int').implementation = function (status) {
            console.log(`[+] Blocked System.exit(${status})`);
            // 完全阻止退出调用
            showJavaStacks();
            return; // 不调用原始方法
        };

        // 拦截 Process.killProcess()
        var Process = Java.use('android.os.Process');
        Process.killProcess.implementation = function (pid) {
            var currentPid = Process.myPid();
            if (pid === currentPid) {
                console.log(`[+] Blocked Process.killProcess(self)`);
                showJavaStacks();
                return; // 阻止自杀
            }
            // 允许杀死其他进程
            return this.killProcess(pid);
        };

        // 可选：拦截 finishAffinity()
        var Activity = Java.use('android.app.Activity');
        Activity.finishAffinity.implementation = function () {
            console.log(`[+] Blocked Activity.finishAffinity()`);
            // 阻止关闭所有 Activity
            showJavaStacks();
            return;
        };
    });
    console.warn("[*] hook_monitor_crash is injected");
}

hook_monitor_crash();
