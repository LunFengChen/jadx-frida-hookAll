// Monitor Toast messages
// 监控 Toast 消息（拦截show、修改内容、主动弹Toast）
function showJavaStacks() {
    const LogClass = Java.use("android.util.Log");
    console.log(LogClass.getStackTraceString(Java.use("java.lang.Exception").$new()));
}

function hook_monitor_toast() {
    Java.perform(function () {
        var class_Toast = Java.use("android.widget.Toast");
        class_Toast.show.implementation = function () {
            const classname_toast = this.getClass().getName();
            console.warn(`[*] classname: ${classname_toast} , toast show() is called!`);
            
            var view = this.getView();
            if (view) {
                var context = view.getContext();
                var messageId = context.getResources().getIdentifier('message', 'id', 'android');
                var foundView = view.findViewById(messageId);
                if (foundView) {
                    var textView = Java.cast(foundView, Java.use("android.widget.TextView"));
                    var originalText = textView.getText().toString();

                    // Filtering logic: Example - bypass toasts containing specific keywords.
                    const textToBypass = "请升级"; // You can change this keyword.
                    if (originalText.includes(textToBypass)) {
                        console.log(`[*] Bypassing toast with text: "${originalText}"`);
                        return; // By not calling this.show(), we prevent the toast from appearing.
                    }

                    var newText = originalText + " hooked!";
                    var javaString = Java.use('java.lang.String').$new(newText);
                    textView.setText(javaString);
                    console.warn(`[*] Toast's text is [${originalText} -> ${newText}]!`);
                } else {
                    console.log("[*] Toast content view not found!");
                }
            }

            showJavaStacks();
            return this.show();
        }
    })
    console.warn(`[*] hook_monitor_toast is injected !`);
}

hook_monitor_toast();

// ========== 主动弹Toast ==========
// 我们自己主动弹toast
function showToast(message) {
    Java.perform(function() {
        // 获取当前应用的 Context
        const context = Java.use('android.app.ActivityThread')
            .currentApplication()
            .getApplicationContext();
        
        // 创建 Toast 并显示
        const Toast = Java.use('android.widget.Toast');
        const String = Java.use('java.lang.String');
        
        // 在主线程执行
        Java.scheduleOnMainThread(function() {
            // 创建 Toast 对象
            const toast = Toast.makeText(
                context,
                String.$new(message),
                Toast.LENGTH_LONG.value
            );
            
            // 显示 Toast
            toast.show();
            
            console.log("[+] Toast 已弹出: " + message);
        });
    });
}

// 使用示例
// showToast('Frida控制Toast!');

/*
关于 Toast (吐司) 的详解

Toast 是 Android 中那种浮在屏幕下方、过几秒自动消失的黑色小提示框。

逆向价值：
1. 定位逻辑的绝佳线索：
   - App 经常会弹出提示：“登录失败”、“签名错误”、“验证码有误”。
   - 这些提示就是 Toast。
   - Hook Toast.show()，打印出堆栈，就能直接定位到“判断失败”的代码位置！
   - 这是逆向分析中最快找到关键判断逻辑的方法之一。

2. 验证修改结果：
   - 我们可以 Hook Toast 修改显示的文字，用来标记我们是否成功注入。
   - 或者主动调用 Toast (如脚本末尾的 `showToast` 函数) 来输出调试信息到屏幕上，不用一直盯着 Logcat。

速记：
1. 看到界面提示“XXX错误”，马上 Hook Toast。
2. 打印出的堆栈里，`show()` 的上一层调用通常就是 `if (failed) { show("错误") }` 的地方。
*/
