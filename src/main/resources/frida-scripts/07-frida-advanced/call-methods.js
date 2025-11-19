// Active method invocation examples
// Java层主动调用方法

// ========== 静态方法直接调用 ==========
function callStaticMethod() {
    Java.perform(function() {
        var ClassName = Java.use("com.zj.wuaipojie.Demo"); 
        var result = ClassName.privateFunc("传参");
        console.log("Static method result:", result);
    });
}

// ========== 对象方法调用（从内存中获取实例）==========
function callInstanceMethod() {
    var ret = null;
    Java.perform(function () {
        Java.choose("com.zj.wuaipojie.Demo", {    // 要hook的类
            onMatch: function(instance) {
                ret = instance.privateFunc("aaaaaaa"); // 要hook的方法
            },
            onComplete: function() {
                console.log("Instance method result: " + ret);
            }
        });
    });
    return ret;
}

// ========== 处理 Byte Array ==========
function createByteArray() {
    Java.perform(function() {
        var arg = Java.use("java.lang.String").$new("123456").getBytes();
        console.log("Byte array created:", arg);
    });
}

// ========== 处理 Application ==========
function getApplication() {
    Java.perform(function() {
        var currentApp = Java.use("android.app.ActivityThread").currentApplication();
        console.log("Application:", currentApp);
    });
}

// ========== 处理 Context ==========
function getContext() {
    Java.perform(function() {
        var context = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();
        console.log("Context:", context);
    });
}

// ========== 处理 String Array ==========
function createStringArray() {
    Java.perform(function() {
        var arr1 = Java.array("Ljava.lang.String", ["a1", "23"]);
        console.log("String array:", arr1);
    });
}

// ========== 处理 Integer ==========
function createInteger() {
    Java.perform(function() {
        var JavaClass_Integer = Java.use("java.lang.Integer");
        var intValue = JavaClass_Integer.$new(1234);
        console.log("Integer:", intValue);
    });
}

// ========== 处理 Boolean ==========
function createBoolean() {
    Java.perform(function() {
        var JavaClass_Boolean = Java.use("java.lang.Boolean");
        var boolValue = JavaClass_Boolean.$new(false);
        console.log("Boolean:", boolValue);
    });
}

// ========== 处理 Object Array ==========
function createObjectArray() {
    Java.perform(function() {
        // 对于基本类型数组，Frida会将其包装成一个特殊对象，该对象有一个$w属性，指向真正的Java数组
        var arr1 = Java.array("Ljava.lang.String", ["123", "2313"]); 
        
        var arg = Java.array("Ljava.lang.Object", [
            Java.cast(arr1.$w, "java.lang.Object"), // 因为arr1是js数组，需要用.$w转向真正的数组
            "1222", // 字符串可以直接传
            Java.use("java.lang.Integer").$new(-1), // 不能直接传-1
            Java.use("java.lang.Boolean").$new(false), // 不能直接传false和true
            Java.use("android.app.ActivityThread").currentApplication().getApplicationContext(), // context
            null, // null 可以直接传
            Java.use("java.lang.Boolean").$new(false),
            ""
        ]);
        
        console.log("Object array:", arg);
    });
}

// 使用示例
// callStaticMethod();
// callInstanceMethod();
