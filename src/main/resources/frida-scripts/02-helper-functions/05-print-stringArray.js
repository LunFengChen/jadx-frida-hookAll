// 功能：打印字符串数组 String[]
function showStringArray(strObj){
    var JDKClass_Array = Java.use("java.lang.reflect.Array");
    console.log("String Array, length=" + JDKClass_Array.getLength(strObj));
    for (let i=0; i< JDKClass_Array.getLength(strObj); i++){
        console.log("  [" + i + "]: " + JDKClass_Array.get(strObj, i));
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
