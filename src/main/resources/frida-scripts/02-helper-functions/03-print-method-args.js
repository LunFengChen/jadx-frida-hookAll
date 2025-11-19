// 功能：打印函数的所有参数及其类型
function showMethodArgs(args) {
    for (var i = 0; i < args.length; i++) {
        console.log("  arg[" + i + "]: " + args[i]);
        if (args[i] != null) {
            console.log("    type: " + args[i].getClass().getName());
        }
    }
}

// 注意事项：
// 1. 使用 arguments 可以获取所有传入的参数
// 2. 对于 Java 对象，使用 getClass().getName() 获取准确的类型
// 3. 如果参数是基本类型，会自动装箱为对象类型

// 使用示例:
// function hook_monitor_yourMethod(){
//     Java.perform(function () {
//         let com_example_YourClass = Java.use("com.example.YourClass");
//         com_example_YourClass["yourMethod"].implementation = function (arg1, arg2) {
//             console.log(`[->] com_example_YourClass.yourMethod is called! args are as follows:`);
//             showMethodArgs(arguments);
//             var retval = this["yourMethod"](arg1, arg2);
//             console.log(`[<-] com_example_YourClass.yourMethod ended! \n    retval= ${retval}`);
//             return retval;
//         };
//     });
//     console.warn(`[*] hook_monitor_yourMethod is injected!`);
// };
// hook_monitor_yourMethod();
