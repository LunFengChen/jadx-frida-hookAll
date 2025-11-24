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
