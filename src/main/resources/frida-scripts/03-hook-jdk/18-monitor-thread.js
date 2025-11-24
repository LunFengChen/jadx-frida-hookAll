// Monitor Thread operations
// 监控线程创建与启动
// java.lang.Thread
// 用途：多线程执行。
// 逆向价值：**中等**。
//           1. 定位反调试逻辑（通常会在独立的子线程中轮询检测）。
//           2. 分析关键业务的异步执行流程。
//           3. 确定线程名称，辅助定位代码（如 "OkHttp Dispatcher", "Retrofit-Idle"）。
function hook_monitor_thread() {
    Java.perform(function () {
        // Helper function to print stack trace
        function showJavaStacks() {
            console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        }

        let java_lang_Thread = Java.use("java.lang.Thread");

        // 1. 监控 Thread 构造函数 (Runnable)
        // 查看谁在创建线程，以及线程的任务是什么
        java_lang_Thread["$init"].overload('java.lang.Runnable').implementation = function (target) {
            console.log(`\n[->] java_lang_Thread.$init(Runnable) is called!`);
            // 尝试获取 Runnable 的类名，这通常能直接对应到匿名内部类或具体任务类
            let runnableName = target.$className;
            console.log(`    ->target class= ${runnableName}`);
            showJavaStacks();
            return this["$init"](target);
        };

        // 2. 监控 Thread 构造函数 (Runnable, String name)
        // 很多 App 会给重要线程命名，这是极好的线索
        java_lang_Thread["$init"].overload('java.lang.Runnable', 'java.lang.String').implementation = function (target, name) {
            console.log(`\n[->] java_lang_Thread.$init(Runnable, String) is called!`);
            let runnableName = target.$className;
            console.log(`    ->target class= ${runnableName}`);
            console.log(`    ->thread name= ${name}`);
            showJavaStacks();
            return this["$init"](target, name);
        };
        
        // 3. 监控 Thread.start()
        // 线程真正开始执行的时机
        java_lang_Thread["start"].implementation = function () {
            let name = this.getName();
            let id = this.getId();
            console.log(`\n[->] java_lang_Thread.start() is called!`);
            console.log(`    ->ID= ${id}`);
            console.log(`    ->Name= ${name}`);
            // showJavaStacks(); // start 的调用栈通常就是创建者的调用栈
            return this["start"]();
        };
        
        // 4. 监控 Thread.run()
        // 注意：直接 Hook Thread.run 可能会产生海量日志，因为所有线程（包括系统线程）都会执行。
        // 建议结合 Thread Name 进行过滤。
        /*
        java_lang_Thread["run"].implementation = function () {
            let name = this.getName();
            if (name.includes("AntiDebug") || name.includes("Monitor")) {
                 console.log(`[->] java_lang_Thread.run() executing specific thread: ${name}`);
            }
            return this["run"]();
        };
        */
    });
    console.warn(`[*] hook_monitor_thread is injected!`);
}
hook_monitor_thread();
