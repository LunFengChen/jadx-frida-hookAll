// Monitor SharedPreferences operations
// 监控 SharedPreferences 读写
// android.content.SharedPreferences: Android轻量级存储类，用于保存Key-Value数据。
// 用途：存储配置信息、Token、User ID、功能开关等。
// 逆向价值：**中等偏高**。常用于查找持久化存储的敏感信息（有时Token会明文存储），或者定位读取配置的代码位置。
function hook_monitor_SharedPreferences() {
    Java.perform(function () {
        // Helper function to print stack trace
        function showJavaStacks() {
            console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        }

        // SharedPreferences.Editor 接口的实现类通常是 android.app.SharedPreferencesImpl$EditorImpl
        // 但直接 hook 接口实现类比较麻烦，我们可以 hook 接口方法，或者找到具体实现类
        // 这里尝试 hook android.app.SharedPreferencesImpl$EditorImpl
        
        try {
            let EditorImpl = Java.use("android.app.SharedPreferencesImpl$EditorImpl");

            // putString
            // 作用: 写入字符串配置。
            // 逆向场景：监控App保存了什么信息到本地（如登录成功后保存Token）。
            EditorImpl["putString"].implementation = function (key, value) {
                let result = this["putString"](key, value);
                console.log(`[->] SharedPreferences.Editor.putString is called!`);
                console.log(`    ->key= ${key}`);
                console.log(`    ->value= ${value}`);
                showJavaStacks();
                return result;
            };

            // putInt
            // 作用: 写入整数配置。
            EditorImpl["putInt"].implementation = function (key, value) {
                let result = this["putInt"](key, value);
                console.log(`[->] SharedPreferences.Editor.putInt is called!`);
                console.log(`    ->key= ${key}`);
                console.log(`    ->value= ${value}`);
                showJavaStacks();
                return result;
            };
            
            // putBoolean
            // 作用: 写入布尔值配置。
            // 逆向场景：监控功能开关的状态（如 is_vip, is_first_run）。
            EditorImpl["putBoolean"].implementation = function (key, value) {
                let result = this["putBoolean"](key, value);
                console.log(`[->] SharedPreferences.Editor.putBoolean is called!`);
                console.log(`    ->key= ${key}`);
                console.log(`    ->value= ${value}`);
                showJavaStacks();
                return result;
            };

        } catch (e) {
            console.warn("SharedPreferencesImpl$EditorImpl not found (might be different Android version): " + e);
        }
        
        // 也可以尝试 Hook android.app.SharedPreferencesImpl 的 getXxx 方法
        try {
            let SharedPreferencesImpl = Java.use("android.app.SharedPreferencesImpl");
            
            // getString
            // 作用: 读取字符串配置。
            // 逆向场景：监控App读取了哪些本地配置，用于定位关键逻辑（如读取Host、读取Token）。
            SharedPreferencesImpl["getString"].implementation = function(key, defValue) {
                 let result = this["getString"](key, defValue);
                 console.log(`[->] SharedPreferences.getString is called!`);
                 console.log(`    ->key= ${key}`);
                 console.log(`    ->result= ${result}`);
                 return result;
            }
            
        } catch(e) {
            console.warn("SharedPreferencesImpl not found: " + e);
        }

    });
    console.warn(`[*] hook_monitor_SharedPreferences is injected!`);
}

hook_monitor_SharedPreferences();

/*
关于 SharedPreferences (SP) 的详解

SharedPreferences 是 Android 提供的一种轻量级的数据存储方式，底层基于 XML 文件。
文件通常存储在 `/data/data/包名/shared_prefs/` 目录下。

逆向价值：
1. 敏感信息泄露：
   - 很多开发者的安全意识不足，会把 Token, SessionId, UserID 甚至密码明文存在 SP 里。
   - Hook `putString` 就像在看 App 的日记本。

2. 功能开关：
   - 很多 App 的功能开关（如 `is_vip`, `show_ads`, `debug_mode`）是保存在 SP 里的。
   - Hook `getBoolean` 并修改返回值，是破解会员、去广告最简单的手段之一。

3. 设备指纹：
   - App 生成的唯一设备 ID (UUID/GUID) 通常会持久化保存在 SP 里，卸载重装后还在。

速记：
1. 看到 `putString("token", ...)`，恭喜你，拿到 Token 了。
2. 看到 `getBoolean("is_vip")`，这就是我们要改的地方。
3. 它的底层实现是 `SharedPreferencesImpl$EditorImpl`，直接 Hook 接口是没用的，必须 Hook 实现类。
*/
