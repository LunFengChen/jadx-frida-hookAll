// 功能：打印对象数组 Object[]
function showObjectArray(objArr, name) {
    if (objArr == null) return;
    var length = objArr.length;
    console.log(name + ' length: ' + length);
    for (let i = 0; i < length; i++) {
        var item = objArr[i];
        if (item != null && item.getClass().getName() === "[B") {
            var str = Java.use('java.lang.String').$new(Java.array('byte', item)).toString();
            console.log('  [' + i + '] = (byte[]) ' + str);
        } else {
            console.log('  [' + i + '] = ' + (item != null ? item.toString() : 'null'));
        }
    }
}

// 注意事项：
// 1. 专门用于打印 Object[] 类型的数组
// 2. 特别处理了 byte[] 类型的元素，将其转换为字符串显示
// 3. 对于其他类型的元素，调用 toString() 方法

// 使用示例:
// function hook_monitor_yourMethod(){
//     Java.perform(function () {
//         let com_example_YourClass = Java.use("com.example.YourClass");
//         com_example_YourClass["yourMethod"].implementation = function (objArray) {
//             console.log(`[->] com_example_YourClass.yourMethod is called! args are as follows:`);
//             showObjectArray(objArray, "objArray");
//             var retval = this["yourMethod"](objArray);
//             console.log(`[<-] com_example_YourClass.yourMethod ended! \n    retval= ${retval}`);
//             return retval;
//         };
//     });
//     console.warn(`[*] hook_monitor_yourMethod is injected!`);
// };
// hook_monitor_yourMethod();

/*
关于 打印对象数组 (Print Object Array) 的详解

这是 `05-print-stringArray.js` 的通用版。
专门处理 `Object[]` 类型的数组。

逆向价值：
- 很多混淆后的代码会用 `Object[]` 来传递一组异构参数。
- 比如 `doSomething(Object[] args)`，里面可能 args[0] 是 Context，args[1] 是 String，args[2] 是 Map。
- 用这个脚本可以一次性打印出数组里每个元素的 toString() 结果，快速理清参数含义。

速记：
1. 遇到 `Object[]`，用这个。
2. 遇到 `String[]`，用这个也行，用 05 也行。
*/
