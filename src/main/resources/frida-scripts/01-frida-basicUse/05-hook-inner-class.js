// Hook内部类
function hook_innerClass(){
    Java.perform(function(){
        // 内部类使用 $ 符号连接, 注意在jadx中实际上搜索要用.连接
        let com_xiaofeng_Demo_innerClass = Java.use("com.xiaofeng.Demo$innerClass");
        console.log("Inner class found:", com_xiaofeng_Demo_innerClass);
        
        com_xiaofeng_Demo_innerClass["$init"].implementation = function(str){
            console.log(`[->] com_xiaofeng_Demo$innerClass.$init is called! args are as follows:\n    ->str= ${str}`);
            var retval = this["$init"](str);
            console.log(`[<-] com_xiaofeng_Demo$innerClass.$init ended! \n    retval= ${retval}`);
            return retval;
        };
    });
    console.warn(`[*] hook_innerClass is injected!`);
};
hook_innerClass();
