// 功能：打印字符串数组 String[]
function showStringArray(strArr) {
    if (strArr == null) return;
    var JavaClass_Array = Java.use('java.lang.reflect.Array');
    var length = JavaClass_Array.getLength(strArr);
    console.log('String array length: ' + length);
    for (let i = 0; i < length; i++) {
        var item = JavaClass_Array.get(strArr, i);
        console.log('  [' + i + '] = ' + (item != null ? item.toString() : 'null'));
    }
}

// 注意事项：
// 1. 使用 java.lang.reflect.Array 处理数组更通用
// 2. 也适用于其他类型的数组，如 int[]、Object[] 等
// 3. 如果数组为 null，会抛出异常，建议先判断

// 使用示例:
// function hook_monitor_yourMethod(){
//     Java.perform(function () {
//         let com_example_YourClass = Java.use("com.example.YourClass");
//         com_example_YourClass["yourMethod"].implementation = function (strArray) {
//             console.log(`[->] com_example_YourClass.yourMethod is called! args are as follows:`);
//             showStringArray(strArray);
//             var retval = this["yourMethod"](strArray);
//             console.log(`[<-] com_example_YourClass.yourMethod ended! \n    retval= ${retval}`);
//             return retval;
//         };
//     });
//     console.warn(`[*] hook_monitor_yourMethod is injected!`);
// };
// hook_monitor_yourMethod();

/*
关于 打印数组 (Print Array) 的详解

Java 中的数组（如 `String[]`, `int[]`, `Object[]`）在 Frida 中通常表现为一个对象引用。
直接打印只能看到类型和哈希码。

原理：
使用 `java.lang.reflect.Array` 反射类来操作数组。
- `Array.getLength(arr)`: 获取长度。
- `Array.get(arr, index)`: 获取指定索引的元素。

逆向价值：
1. 查看参数列表：
   - 很多命令行执行（Runtime.exec）或参数传递使用 `String[]`。
2. 批量数据分析：
   - 加密函数的输入有时是 byte[] (其实也是数组，虽然我们有专门的 hex 打印函数，但原理类似)。

速记：
1. 只要是数组（除了 byte[] 建议用 hex），都可以用这个模板打印。
2. 反射是通用的，不用关心具体是 String[] 还是 Integer[]。
*/
