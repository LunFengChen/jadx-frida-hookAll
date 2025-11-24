// Monitor Collections.sort operations
// 监控排序操作
function printStacks() {
    console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
}

Java.perform(function() {
    var collections = Java.use("java.util.Collections");
    
    collections.sort.overload('java.util.List').implementation = function (a) {
        var result = Java.cast(a, Java.use("java.util.ArrayList"));
        console.log("collections.sort List: ", result.toString());
        printStacks();
        return this.sort(a);
    }
    
    collections.sort.overload('java.util.List', 'java.util.Comparator').implementation = function (a, b) {
        var result = Java.cast(a, Java.use("java.util.ArrayList"));
        console.log("collections.sort List Comparator: ", result.toString());
        printStacks();
        return this.sort(a, b);
    }
    
    console.warn("[*] hook_monitor_Collections is injected");
});

/*
关于 Collections 工具类的详解

java.util.Collections 是一个操作 Set、List 和 Map 等集合的工具类。

逆向价值：
1. sort (排序)：
   - 很多签名算法要求参数必须按字母序排序 (Dictionary Order)。
   - App 通常会调用 `Collections.sort(list, comparator)`。
   - Hook 这里可以看到排序前的乱序参数，以及排序后的有序参数。
   - 还能看到使用的 Comparator 规则。

2. synchronizedXxx (线程安全包装)：
   - 如果看到 `Collections.synchronizedMap`，说明这部分逻辑涉及多线程操作，可能比较关键。

速记：
1. 看到 `Collections.sort`，立刻警觉，这很可能是签名算法的一部分！
*/
