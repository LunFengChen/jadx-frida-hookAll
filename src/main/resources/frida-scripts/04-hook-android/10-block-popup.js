// Block popup windows (Dialog, Toast, System popups)
// 拦截所有弹窗 - WindowManager底层拦截
Java.perform(function() {
    // ===== 方式1：Hook WindowManager.addView() - 全局拦截 =====
    const WindowManagerGlobal = Java.use('android.view.WindowManagerGlobal');
    const View = Java.use('android.view.View');

    // 原始方法引用
    const addViewOriginal = WindowManagerGlobal.addView.overload(
        'android.view.View', 
        'android.view.ViewGroup$LayoutParams',
        'android.view.Display',
        'android.view.Window'
    );

    // Hook 实现
    WindowManagerGlobal.addView.implementation = function(view, params, display, window) {
        try {
            const windowType = params.type.value; // 获取窗口类型
            const viewClass = view.getClass().getName();

            // 常见弹窗类型值（不同 Android 版本可能不同）
            const POPUP_TYPES = new Set([
                2002, // TYPE_PHONE
                2003, // TYPE_SYSTEM_ALERT
                2006, // TYPE_SYSTEM_OVERLAY
                2010, // TYPE_SYSTEM_ERROR
                2038  // TYPE_APPLICATION_OVERLAY (Android O+)
            ]);

            // 判断是否为弹窗类型
            if (POPUP_TYPES.has(windowType) || 
                viewClass.includes("Dialog") || 
                viewClass.includes("Popup")) {

                console.log(`🚫 BLOCKED POPUP [Type:${windowType}] [View:${viewClass}]`);
                return; // 直接拦截
            }
        } catch (e) { /* 错误处理 */ }

        // 非弹窗继续执行
        addViewOriginal.call(this, view, params, display, window);
    };

    // ===== 方式2：Hook Dialog.show() - 精准拦截 =====
    const Dialog = Java.use('android.app.Dialog');

    Dialog.show.implementation = function() {
        const dialogClass = this.getClass().getName();
        const context = this.getContext();
        const pkgName = context.getPackageName();

        // 示例：拦截包含特定关键词的弹窗
        if (dialogClass.includes("AdDialog") || 
            dialogClass.includes("Update")) {
            console.log(`🚫 BLOCKED DIALOG [${dialogClass}]`);
            return; // 拦截显示
        }

        // 允许正常弹窗
        console.log(`✅ Allowed dialog: ${dialogClass}`);
        this.show(); // 继续执行原始方法
    };

    // ===== 方式3：Hook Toast 弹窗 =====
    try {
        const ToastTN = Java.use('android.widget.Toast$TN');

        ToastTN.handleShow.implementation = function() {
            const text = this.mText ? this.mText.value : ""; // 获取Toast文本
            if (text && text.includes("广告")) {
                console.log(`🚫 BLOCKED TOAST: ${text}`);
                return;
            }
            this.handleShow();
        };
    } catch (e) {
        console.log("Toast$TN hook failed:", e.message);
    }

    console.log("🎯 Frida弹窗拦截器已激活！");
});

/*
关于 弹窗拦截 (Block Popup) 的详解

这是一个功能型脚本，而非监控型脚本。它的目的是为了“清爽”的逆向环境。

原理：
1. 全局拦截 (WindowManager):
   - 所有的悬浮窗（Toast, System Alert, Overlay）最终都要通过 `WindowManager.addView` 添加到屏幕。
   - 通过判断 `params.type` 可以精准识别并拦截系统级弹窗（如“请勿遮挡屏幕”提示）。

2. Dialog 拦截:
   - 针对应用内的广告弹窗、更新弹窗。
   - 通过判断 Dialog 类名是否包含 "Ad", "Update" 等关键词进行过滤。

3. Toast 拦截:
   - 针对烦人的文字提示。

逆向价值：
- 很多 App 检测到 Frida 或 Root 后，会弹出一个不可取消的 Dialog 强制用户退出。
- Hook 这里直接 `return`，就能绕过这种“软”保护，强行进入 App。

速记：
1. 遇到“检测到环境异常，请退出”的弹窗，用这个脚本。
2. 遇到满屏广告，用这个脚本。
*/
