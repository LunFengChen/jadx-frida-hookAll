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
