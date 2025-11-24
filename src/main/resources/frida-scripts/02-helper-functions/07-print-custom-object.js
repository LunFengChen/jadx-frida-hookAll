// 功能：打印自定义对象 - 通过 Java.cast 转换类型

// 方法1: 打印 Byte Array 对象
function printByteArray(objArr) {
    var JDKClass_Byte = Java.use("[B");
    var buffer = Java.cast(objArr[0], JDKClass_Byte);
    var res = Java.array('byte', buffer);
    console.log("Byte Array: " + res);
    return res;
}

// 方法2: 打印 Map 对象
function printMapObject(map){
    console.log("Map Type: " + map.getClass().getName());
    var mapClass = map.getClass().getName();
    var map_ = Java.cast(map, Java.use(mapClass));
    console.log("Map Content: " + map_.toString());
    return map_;
}

// 方法3: 打印任意对象
function printObject(obj) {
    if (obj == null) {
        console.log("Object is null");
        return;
    }
    console.log("Object Type: " + obj.getClass().getName());
    console.log("Object Content: " + obj.toString());
}

// 方法4: 获取对象所有字段
function printObjectFields(obj) {
    if (obj == null) {
        console.log("Object is null");
        return;
    }
    var clazz = obj.getClass();
    var fields = clazz.getDeclaredFields();
    console.log("Object Type: " + clazz.getName());
    console.log("Fields:");
    for (var i = 0; i < fields.length; i++) {
        fields[i].setAccessible(true);
        var fieldName = fields[i].getName();
        var fieldValue = fields[i].get(obj);
        console.log("  " + fieldName + " = " + fieldValue);
    }
}

// 注意事项：
// 1. Java.cast 用于将对象转换为指定类型
// 2. 对于未知类型的对象，先用 getClass().getName() 查看类型
// 3. printObjectFields 可以查看对象内部所有字段的值，反射分析很有用
// 4. setAccessible(true) 可以访问私有字段

// 使用示例:
// function hook_monitor_yourMethod(){
//     Java.perform(function () {
//         let com_example_YourClass = Java.use("com.example.YourClass");
//         com_example_YourClass["yourMethod"].implementation = function (customObj) {
//             console.log(`[->] com_example_YourClass.yourMethod is called! args are as follows:`);
//             printObject(customObj);
//             printObjectFields(customObj);
//             var retval = this["yourMethod"](customObj);
//             console.log(`[<-] com_example_YourClass.yourMethod ended! \n    retval= ${retval}`);
//             return retval;
//         };
//     });
//     console.warn(`[*] hook_monitor_yourMethod is injected!`);
// };
// hook_monitor_yourMethod();

/*
关于 打印自定义对象 (Reflect Custom Object) 的详解

Frida Hook 到一个自定义对象 (如 `com.example.User`) 时，直接 `console.log(obj)` 通常只打印地址。
我们想知道它内部的成员变量（字段）的值。

原理：
利用 Java 反射 (Reflection) 机制。
1. `obj.getClass().getDeclaredFields()`: 获取所有字段。
2. `field.setAccessible(true)`: 强行赋予访问权限（即使是 private 字段）。
3. `field.get(obj)`: 读取字段值。

逆向价值：
1. "透视眼"：
   - 无需去 Jadx 里辛苦分析这个类有哪些 getter 方法。
   - 直接用这个脚本，瞬间看清对象内部的所有秘密。
   - 比如一个 Config 对象，可能包含 API URL、AES Key、Debug 开关等。

速记：
1. 只要拿到一个 Object，用 `printObjectFields(obj)`，它就得把所有家当都交出来。
2. 这是查看混淆代码中数据结构的神器。
*/
