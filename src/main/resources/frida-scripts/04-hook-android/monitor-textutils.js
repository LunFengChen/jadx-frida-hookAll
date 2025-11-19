// Monitor TextUtils.isEmpty
// 监控文本判空（用于寻找输入框定位、硬编码密码爆破）
function showStacks() {
    console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
}

Java.perform(function() {
    var textUtils = Java.use("android.text.TextUtils");
    textUtils.isEmpty.implementation = function (a) {
        // 可以过滤特定内容
        if (a == "TURJNk1EQTZNREE2TURBNk1EQTZNREE9") { 
            console.log("textUtils.isEmpty: ", a);
            showStacks();
        }
        return this.isEmpty(a);
    }
    
    console.warn("[*] hook_monitor_TextUtils is injected");
});
