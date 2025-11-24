// Hook重载方法：有些方法的函数名相同，需要根据参数类型来指定
function hook_overload() {
    Java.perform(function () {
        let com_xiaofeng_Demo = Java.use("com.xiaofeng.Demo");

        // overload定义重载函数，根据函数的参数类型填
        // .overload()
        // .overload('自定义参数')  
        // .overload('int')
        // 如果没指定，frida也会报错然后提示有哪些类型，可以从中扣代码
        com_xiaofeng_Demo["method"].overload('com.xiaofeng.Demo$Animal', 'java.lang.String').implementation = function (a, b) {
            console.log(`[->] com_xiaofeng_Demo.method is called! args are as follows:\n    ->a= ${a}\n    ->b= ${b}`);
            var retval = this["method"](a, b);
            console.log(`[<-] com_xiaofeng_Demo.method ended! \n    retval= ${retval}`);
            return retval;
        };
    });
    console.warn(`[*] hook_overload is injected!`);
};
hook_overload();

/*
关于方法重载 (Overload) 的详解

在 Java 中，同一个类可以有多个同名方法，只要它们的参数列表不同。这叫重载。
Frida 在 Hook 时，必须明确指定你要 Hook 哪一个具体的重载版本。

使用 .overload(...)：
1. 无参数方法：
   .overload()

2. 基本类型参数：
   .overload('int')
   .overload('boolean', 'float')

3. 引用类型参数：
   .overload('java.lang.String')
   .overload('android.content.Context')

4. 数组类型：
   .overload('[B')  // byte[]
   .overload('[Ljava.lang.String;') // String[]

技巧 - 自动获取签名：
如果你不知道正确的 overload 签名，可以直接写 .overload()。
Frida 会在控制台报错，并列出所有可用的 overload 签名。
例如：
Error: target.method.overload is ambiguous; possible matches:
    .overload('int')
    .overload('java.lang.String')
你只需要复制报错信息里你想要的那个即可。

速记：
1. 只要报错 "ambiguous" (模棱两可)，就是没指定 overload。
2. 内部类要用 $ 符号，如 'com.example.Outer$Inner'。
*/
