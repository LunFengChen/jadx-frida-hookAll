// Monitor SharedPreferences and ContentResolver
// 监控内部存储和应用间数据传递
Java.perform(function() {
    // Hook内部存储api，打印出存储的数据
    var sp = Java.use("android.app.SharedPreferencesImpl$EditorImpl");
    
    sp.putBoolean.overload('java.lang.String', 'boolean').implementation = function(arg1,arg2){
        console.log("[SharedPreferencesImpl] putBoolean -> key: "+arg1+" = "+arg2);
        return this.putBoolean(arg1,arg2);
    }

    sp.putString.overload('java.lang.String', 'java.lang.String').implementation = function(arg1,arg2){
        console.log("[SharedPreferencesImpl] putString -> key: "+arg1+" = "+arg2);
        return this.putString(arg1,arg2);
    }

    sp.putInt.overload('java.lang.String', 'int').implementation = function(arg1,arg2){
        console.log("[SharedPreferencesImpl] putInt -> key: "+arg1+" = "+arg2);
        return this.putInt(arg1,arg2);
    }

    sp.putFloat.overload('java.lang.String', 'float').implementation = function(arg1,arg2){
        console.log("[SharedPreferencesImpl] putFloat -> key: "+arg1+" = "+arg2);
        return this.putFloat(arg1,arg2);
    }

    sp.putLong.overload('java.lang.String', 'long').implementation = function(arg1,arg2){
        console.log("[SharedPreferencesImpl] putLong -> key: "+arg1+" = "+arg2);
        return this.putLong(arg1,arg2);
    }

    // Hook应用程序间数据传递的api，打印出传递数据的uri与具体的字段
    var content = Java.use("android.content.ContentResolver");
    
    content.insert.overload("android.net.Uri","android.content.ContentValues").implementation = function(arg1,arg2){
        console.log("[ContentResolver] *insert -> Uri: "+arg1+"  Values: "+arg2);
        return this.insert(arg1,arg2);
    }

    content.delete.overload("android.net.Uri","java.lang.String","[Ljava.lang.String;").implementation = function(arg1,arg2,arg3){
        console.log("[ContentResolver] *delete -> Uri: "+arg1+"\n  -> arg2: "+arg2+"\n  -> arg3: "+arg3);
        return this.delete(arg1,arg2,arg3);
    }

    content.update.overload('android.net.Uri','android.content.ContentValues','java.lang.String','[Ljava.lang.String;').implementation = function(arg1,arg2,arg3,arg4){
        console.log("[ContentResolver] *update -> Uri: "+arg1+"\n  -> arg2: "+arg2+"\n  -> arg3: "+arg3+"\n  -> arg4: "+arg4);
        return this.update(arg1,arg2,arg3,arg4);
    }

    content.query.overload('android.net.Uri', '[Ljava.lang.String;', 'android.os.Bundle', 'android.os.CancellationSignal').implementation = function(arg1,arg2,arg3,arg4){
        console.log("[ContentResolver] *query -> Uri: "+arg1+"\n  -> arg2: "+arg2+"\n  -> arg3: "+arg3+"\n  -> arg4: "+arg4);
        return this.query(arg1,arg2,arg3,arg4);
    }

    content.query.overload('android.net.Uri', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String').implementation = function(arg1,arg2,arg3,arg4,arg5){
        console.log("[ContentResolver] *query -> Uri: "+arg1+"\n  -> arg2: "+arg2+"\n  -> arg3: "+arg3+"\n  -> arg4: "+arg4+"\n  -> arg5: "+arg5);
        return this.query(arg1,arg2,arg3,arg4,arg5);
    }

    content.query.overload('android.net.Uri', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', 'android.os.CancellationSignal').implementation = function(arg1,arg2,arg3,arg4,arg5,arg6){
        console.log("[ContentResolver] *query -> Uri: "+arg1+"\n  -> arg2: "+arg2+"\n  -> arg3: "+arg3+"\n  -> arg4: "+arg4+"\n  -> arg5: "+arg5+"\n arg6: "+arg6);
        return this.query(arg1,arg2,arg3,arg4,arg5,arg6);
    }
    
    console.warn("[*] hook_monitor_SharedPreferences is injected");
});

/*
关于 Android 存储 (SP & Provider) 的详解

这个脚本同时监控了两种数据存储/共享方式：

1. SharedPreferencesImpl (SP):
   - 這是 Android 框架层的实现类 `android.app.SharedPreferencesImpl$EditorImpl`。
   - 不同于 JDK 版脚本 Hook 接口，这里直接 Hook 了实现类，能抓到更底层的调用。
   - 逆向价值：抓取 Token、修改功能开关（见 JDK 版详解）。

2. ContentResolver (内容解析器):
   - Android 四大组件之一 ContentProvider 的客户端。
   - 用途：App 内部或 App 之间共享数据（如读取通讯录、短信、相册）。
   - 逆向价值：
     - 监控 App 读取了哪些隐私数据（通讯录、短信验证码）。
     - 监控跨进程通信 (IPC) 的数据流动。
     - 某些加固壳会利用 Provider 来传递解密后的 Dex 或配置。

速记：
1. 看到 `content://` 开头的 URI，就是在用 ContentResolver。
2. Hook 这里可以监控到 App 对隐私数据的觊觎。
*/
