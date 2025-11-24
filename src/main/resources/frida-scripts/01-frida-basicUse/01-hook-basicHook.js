// Hook普通方法、打印参数和修改返回值 
function hook_basicHook() { // 封装成函数方便调用和特殊情况再次hook
    Java.perform(function () {// Java.perform()确保代码在Java环境中执行
        // 拿到类名
        let com_xiaofeng_Demo = Java.use("com.xiaofeng.Demo"); 
        // 拿到方法名然后调用implementation进行重写
        com_xiaofeng_Demo["method"].implementation = function (a, b) { 
            // 监控一下输入参数
            console.log(`[->] com_xiaofeng_Demo.method is called! args are as follows:\n    ->a= ${a}\n    ->b= ${b}`);
            
            // 可以修改输入
            // a = 123;
            // b = 456;
            
            // 可以调用原来的方法，获取返回值
            var retval = this["method"](a, b);
            
            // 这里可以监控返回值
            console.log(`[<-] com_xiaofeng_Demo.method ended! \n    retval= ${retval}`);
            
            // 也可以在这里修改返回值， 
            // retval = 2;
            // 但是最好标记好修改后的值
            // console.log(`[<-] com_xiaofeng_Demo.method ended! \n    retval= ${retval} -> 2`);
            return retval;
        };
    });
    // 这个是方便我们判断是否成功注入hook, 防止出现脚本写了但是没调用方便排查原因
    console.warn(`[*] hook_basicHook is injected!`); 
};
hook_basicHook();