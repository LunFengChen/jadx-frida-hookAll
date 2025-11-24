// Monitor Android Log output
// 监控日志输出（用于定位）
Java.perform(function() {
    var log = Java.use("android.util.Log");
    
    log.w.overload('java.lang.String', 'java.lang.String').implementation = function (tag, message) {
        console.log("log.w: ", tag, message);
        return this.w(tag, message);
    }
    
    log.d.overload('java.lang.String', 'java.lang.String').implementation = function (tag, message) {
        console.log("log.d: ", tag, message);
        return this.d(tag, message);
    }
    
    log.e.overload('java.lang.String', 'java.lang.String').implementation = function (tag, message) {
        console.log("log.e: ", tag, message);
        return this.e(tag, message);
    }
    
    log.i.overload('java.lang.String', 'java.lang.String').implementation = function (tag, message) {
        console.log("log.i: ", tag, message);
        return this.i(tag, message);
    }
    
    console.warn("[*] hook_monitor_Log is injected");
});

/*
关于 Log (日志) 的详解

android.util.Log 是 Android 官方的日志工具类。

逆向价值：
1. 捡漏：
   - 很多开发者发布 Release 版时忘了关日志 (Log.d/Log.i)。
   - 日志里可能包含：请求参数、加密前的明文、关键流程的执行状态。
   - 即使 App 混淆了，日志里的 String tag 和 message 通常是明文，是定位代码的绝佳关键词。

2. 恢复被截断的日志：
   - Logcat 有长度限制（通常 4096 字节）。
   - 如果日志太长（如打印了一个巨大的 Base64 或 JSON），Logcat 会显示不全。
   - Hook 这里可以把完整的日志打印出来，或者保存到文件。

速记：
1. 逆向第一步，先看 Logcat。
2. 如果 Logcat 里有一堆 "System.out", "System.err" 或者某些看起来像调试信息的日志，Hook Log 类可以帮你找到是哪行代码打印的（结合 StackTrace）。
*/
