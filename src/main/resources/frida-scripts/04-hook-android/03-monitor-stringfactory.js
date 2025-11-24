// Monitor StringFactory (String construction)
// hook String 的构造函数，字符串生成的地方
Java.perform(function() {
    var stringFactory = Java.use("java.lang.StringFactory");
    
    stringFactory.newStringFromString.implementation = function (a) {
        var retval = this.newStringFromString(a);
        console.log("stringFactory.newStringFromString: ", retval);
        return retval;
    }
    
    stringFactory.newStringFromChars.overload('[C').implementation = function (a) {
        var retval = this.newStringFromChars(a);
        console.log("stringFactory.newStringFromChars: ", retval);
        return retval;
    }
    
    console.warn("[*] hook_monitor_StringFactory is injected");
});

/*
关于 StringFactory 的详解

这个类在标准 JDK 文档中是找不到的，它是 Android 系统特有的内部类 (Hidden API)。
全名：`java.lang.StringFactory`

作用：
它是 Android 优化字符串创建的产物。
所有的 `new String(...)` 操作，在 Android ART 虚拟机底层，最终往往会调用 `StringFactory` 的静态方法来分配内存和初始化。

为什么 Hook 它？
1. 它是 String 构造函数的底层实现。
2. Hook `java.lang.String` 的构造函数有时候会漏掉一些情况（或者是被系统层面的优化绕过）。
3. Hook `StringFactory` 可以更全面地监控字符串的产生，尤其是从 char[] 或 byte[] 转换来的字符串。

速记：
1. 这是一个 Android 特有的类，普通 Java 程序里没有。
2. 觉得 Hook String 构造函数抓不到包的时候，试试 Hook 这个。
*/
