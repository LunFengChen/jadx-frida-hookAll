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
