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
