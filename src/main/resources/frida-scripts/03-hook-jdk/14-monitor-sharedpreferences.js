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
