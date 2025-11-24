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

/*
关于 TextUtils 的详解

android.text.TextUtils 是 Android 处理字符串的工具类。
最常用的方法是 `isEmpty(str)`。

逆向价值：
1. 定位关键逻辑：
   - 几乎所有的登录、注册、搜索功能，在处理用户输入前，都会调用 `TextUtils.isEmpty` 检查是否为空。
   - Hook 这个方法，并过滤特定的输入（比如你输入的测试账号 "test_user"），可以迅速定位到 UI 层的处理逻辑。
   - 脚本里的 `if (a == "TURJNk1EQTZNREE2TURBNk1EQTZNREE9")` 就是一个示例，你可以把它改成你感兴趣的字符串。

2. 辅助硬编码爆破：
   - 有时候 App 会把硬编码的密钥或 Token 和用户输入做比较。
   - 如果我们在 `isEmpty` 里监控到了一个奇怪的字符串，而我们自己又没输入过它，那它很有可能就是硬编码的密钥！

速记：
1. 这是一个高频调用函数，Hook 时一定要加过滤条件，否则日志会爆炸。
2. 用它来定位“按键点击事件”非常准。
*/
