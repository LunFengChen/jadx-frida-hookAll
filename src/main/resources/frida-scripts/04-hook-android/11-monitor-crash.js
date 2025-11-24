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

/*
关于 崩溃拦截 (Block Crash/Exit) 的详解

App 闪退或退出通常有几种原因：
1. 异常崩溃 (Uncaught Exception)。
2. 主动退出 (System.exit, Process.killProcess)。
3. Activity 栈清空 (finishAffinity)。

逆向价值：
1. 对抗反调试退出：
   - 很多反调试逻辑发现异常后，会直接调用 `System.exit(0)` 或 `killProcess(myPid)` 自杀。
   - Hook 这两个方法并拦截（不执行原方法），可以让 App 即使检测到了也不死！
   - 配合堆栈打印 (`showJavaStacks`)，可以迅速定位是哪行代码触发的退出。

2. 只有活着的 App 才能被分析：
   - 只要 App 不退，我们就有机会继续 Dump 内存、Hook 函数。
   - 这个脚本是“不死鸟”模式的核心。

速记：
1. App 一打开就闪退？挂上这个脚本试试。
2. 如果看到日志里打印了 "Blocked System.exit"，恭喜你，你抓住了反调试的尾巴。
*/
