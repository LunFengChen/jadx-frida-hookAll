// Monitor Android Dialog
Java.perform(function() {
    var Dialog = Java.use('android.app.Dialog');
    
    Dialog.show.implementation = function() {
        console.log('========== Dialog.show() ==========');
        console.log('[Dialog] Class: ' + this.getClass().getName());
        
        // Print stack trace to see where dialog is shown
        console.log('[Dialog] Stack trace:');
        console.log(Java.use('android.util.Log').getStackTraceString(
            Java.use('java.lang.Exception').$new()
        ));
        
        return this.show();
    };
    
    console.log('[+] Dialog monitor installed');
});

/*
关于 Dialog (弹窗) 的详解

Dialog 是 Android 中用于显示覆盖层的小窗口（如 Alert, Prompt, Loading）。

逆向价值：
1. 强制更新/公告弹窗：
   - 很多 App 启动时的“强制更新”或“广告弹窗”就是 Dialog。
   - Hook `Dialog.show()` 可以定位是哪里触发的弹窗。
   - 进阶技巧：Hook `show()` 并直接 `return` (不调用 `this.show()`)，可以屏蔽这些弹窗！

2. 敏感操作确认：
   - 支付确认、删除确认等。
   - 通过堆栈可以反推业务逻辑触发点。

3. 反调试/环境检测警告：
   - “检测到 Root 权限，App 将退出”。
   - 这通常也是一个 Dialog。Hook 这里可以找到检测代码的源头。

速记：
1. 所有的 `AlertDialog`, `ProgressDialog` 最终都继承自 `android.app.Dialog`。
2. 想去掉烦人的弹窗？Hook `show` 然后啥也不做。
*/
