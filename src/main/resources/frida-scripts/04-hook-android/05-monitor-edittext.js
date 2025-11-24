// Monitor EditText.getText (for password cracking)
// 监控输入框内容（用于爆破密码）
function printStacks() {
    console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
}

Java.perform(function() {
    var editText = Java.use("android.widget.EditText");
    editText.getText.overload().implementation = function () {
        var result = this.getText();
        result = Java.cast(result, Java.use("java.lang.CharSequence"));
        console.log("editText.getText: ", result.toString());
        printStacks();
        return result;
    }
    
    console.warn("[*] hook_monitor_EditText is injected");
});

/*
关于 EditText (输入框) 的详解

EditText 是 Android 中用于接收用户输入的控件（通常继承自 TextView）。

逆向价值：
1. 抓取敏感输入：
   - 用户名、密码、验证码、搜索关键词。
   - Hook `getText()` 可以在 App 获取这些输入的那一瞬间截获它们。
   - 即使 App 随后对密码进行了加密，我们在 `getText()` 拿到的依然是明文！

2. 自动填充/爆破辅助：
   - 结合 `setText()`，可以实现自动填写密码进行爆破测试。

速记：
1. 想抓明文密码？Hook `EditText.getText()` 是最简单的方案，比去分析加密算法快得多。
2. 注意：`getText()` 返回的是 `Editable` 对象，需要 `toString()` 才能看到文本内容。
*/
