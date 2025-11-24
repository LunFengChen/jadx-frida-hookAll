// 功能：打印函数的所有参数的准确类型
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

/*
关于 打印方法参数 (Print Method Arguments) 的详解

在 Hook 一个未知方法时，我们往往不知道参数的具体内容和类型。
虽然 Frida 的 `implementation` 函数接收到的参数是 JS 包装对象，但有时我们需要知道它在 Java 层的真实身份。

核心价值：
1. 动态类型分析：
   - Java 是多态的，参数声明是 `Object`，实际传进来的可能是 `String`、`HashMap` 或 `CustomUserClass`。
   - 使用 `obj.getClass().getName()` 可以获取运行时的真实类名。

2. 解决重载歧义：
   - 当遇到同名方法重载时，打印出参数类型可以帮我们确定当前触发的是哪一个重载。

速记：
1. `arguments` 是 JS 的内置关键字，包含所有传入参数。
2. 这里的 `showMethodArgs(arguments)` 可以一键打印所有参数的值和类型，非常适合初步探测。
*/
