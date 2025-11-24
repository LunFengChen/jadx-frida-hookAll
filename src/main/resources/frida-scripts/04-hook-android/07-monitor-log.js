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
