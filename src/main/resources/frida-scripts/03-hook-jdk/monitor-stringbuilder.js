// Monitor StringBuilder and StringBuffer (String concatenation)
// 监控字符串拼接
Java.perform(function() {
    // 字符串拼接 - StringBuilder
    var sb = Java.use("java.lang.StringBuilder");
    sb.toString.implementation = function () {
        var retval = this.toString();
        console.log("StringBuilder.toString: ", retval);
        return retval;
    }

    // 支持多线程 字符串拼接 - StringBuffer
    var sbf = Java.use("java.lang.StringBuffer");
    sbf.toString.implementation = function () {
        var retval = this.toString();
        console.log("StringBuffer.toString: ", retval);
        return retval;
    }
    
    console.warn("[*] hook_monitor_StringBuilder is injected");
});
