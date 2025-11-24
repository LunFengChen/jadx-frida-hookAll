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
