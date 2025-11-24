// Hook字段（静态和非静态）
function hook_field() {
    Java.perform(function () {
        let com_xiaofeng_Demo = Java.use("com.xiaofeng.Demo");

        // 静态字段的修改
        let oldStaticValue = com_xiaofeng_Demo["staticField"].value;
        com_xiaofeng_Demo["staticField"].value = "我是被修改的静态变量"; // 修改
        console.log(`[Static Field] staticField: ${oldStaticValue} -> ${com_xiaofeng_Demo["staticField"].value}`);

        // 非静态字段(对象自己的属性)的修改：得先找到对象，才能找到对象的非静态字段
        // 使用`Java.choose()`枚举类的所有实例(对象)
        Java.choose("com.xiaofeng.Demo", {
            onMatch: function (obj) {
                // 保存原值
                let oldPrivateInt = obj["_privateInt"].value;
                let oldPrivateInt2 = obj["privateInt"].value;
                
                // 修改实例的非静态字段
                obj["_privateInt"].value = "123456"; // 字段名与函数名相同时前面加下划线
                obj["privateInt"].value = 9999;
                
                // 对比修改前后的值
                console.log(`[Instance Field] _privateInt: ${oldPrivateInt} -> ${obj["_privateInt"].value}`);
                console.log(`[Instance Field] privateInt: ${oldPrivateInt2} -> ${obj["privateInt"].value}`);
            },
            onComplete: function () {// 全部匹配完会走这里
                console.log("[*] Hook field completed!");
            }
        });
    });
    console.warn(`[*] hook_field is injected!`);
};
hook_field();

/*
关于 Hook 字段 (Field) 的详解

在 Java 中，字段 (成员变量) 分为两类：
1. 静态字段 (static)：属于类，只有一份。
2. 实例字段 (instance)：属于对象，每个对象都有一份。

Frida 操作字段的核心：
1. 访问属性必须用 `.value`。
   - 错误：`obj.fieldName`
   - 正确：`obj.fieldName.value`

2. 静态字段直接通过 `Java.use()` 得到的类封装器访问。
   - `clazz.staticField.value`

3. 实例字段必须先获取到实例对象 (Instance)。
   - 常见方法：
     a) `Java.choose()`：主动去堆内存里搜寻已经存在的对象。
     b) 在某个方法的 `implementation` 中，使用 `this` 访问当前对象。

4. 命名冲突处理：
   - 如果字段名和方法名相同，Frida 会自动在字段名前加下划线 `_`。
   - 例如：类中有 `someName()` 方法和 `someName` 字段。
   - 访问字段时用 `obj._someName.value`。

速记：
1. 看到 .value 才是拿值，否则拿到的是 Field 对象。
2. 只有静态字段能直接 Hook 修改，实例字段必须先找到对象（choose 或 this）。
3. 字段名和方法名撞车了？前面加个下划线试试。
*/
