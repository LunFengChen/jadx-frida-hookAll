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
