// Monitor Process Execution
// 监控命令执行 (Runtime.exec, ProcessBuilder)
// 用途：监控 App 执行了哪些 Shell 命令。
// 逆向价值：**中等**。
//           1. 检测 Root/Frida (如执行 'su', 'ps', 'ls /data/local/tmp')。
//           2. 业务功能 (如 'ping', 'logcat')。
function hook_monitor_process() {
    Java.perform(function () {
        // Helper function to print stack trace
        function showJavaStacks() {
            console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        }

        // 1. ProcessBuilder.start()
        let ProcessBuilder = Java.use("java.lang.ProcessBuilder");
        ProcessBuilder["start"].implementation = function () {
            let cmdList = this.command();
            let cmdStr = "";
            if (cmdList != null) {
                cmdStr = cmdList.toString();
            }
            console.log(`\n[->] ProcessBuilder.start() is called!`);
            console.log(`    ->command= ${cmdStr}`);
            showJavaStacks();
            return this["start"]();
        };

        // 2. Runtime.exec()
        // Runtime.exec 有多个重载，通常最终都会调用 exec(String[] cmdarray, String[] envp, File dir)
        // 或者 exec(String command, ...)
        let Runtime = Java.use("java.lang.Runtime");
        
        Runtime["exec"].overload('java.lang.String').implementation = function (command) {
            console.log(`\n[->] Runtime.exec(String) is called!`);
            console.log(`    ->command= ${command}`);
            showJavaStacks();
            return this["exec"](command);
        };
        
        Runtime["exec"].overload('[Ljava.lang.String;').implementation = function (cmdarray) {
            console.log(`\n[->] Runtime.exec(String[]) is called!`);
            console.log(`    ->command= ${cmdarray ? cmdarray.toString() : "null"}`);
            showJavaStacks();
            return this["exec"](cmdarray);
        };
        
        // 还有带 envp 和 dir 参数的重载，如果需要更精细可以继续添加
    });
    console.warn(`[*] hook_monitor_process is injected!`);
}
hook_monitor_process();

/*
关于 命令执行 (Runtime.exec/ProcessBuilder) 的详解

在 Android 中，Java 层执行 Shell 命令主要通过 `Runtime.getRuntime().exec()` 或 `new ProcessBuilder().start()`。

底层原理：
最终都会调用 native 层的 `forkAndExec` (在 Android 7.0+ 可能是 `java.lang.ProcessManager` 或 `java.lang.UNIXProcess`)。

逆向价值：
1. Root 检测：
   - App 经常尝试执行 `su` 来判断是否有 Root 权限。
   - 或者执行 `ls /data` 看是否有权限。

2. 环境检测：
   - `getprop ro.debuggable`
   - `ps` 查看正在运行的进程 (检测 frida-server)。
   - `mount` 查看挂载点 (检测 Magisk)。

3. 业务功能：
   - `ping` 网络诊断。
   - `logcat` 收集日志。
   - `am start` 启动其他组件。

速记：
1. 看到 `su`，就是在查 Root。
2. 看到 `ps` 或 `mount`，就是在查环境。
3. Hook 这里可以直接修改命令，比如把 `su` 改成 `id`，从而绕过 Root 检测（让 App 以为执行成功但没拿到 root 权限，或者执行失败）。
*/
