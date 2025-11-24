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
