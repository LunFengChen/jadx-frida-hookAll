// Hook类的构造函数
function hook_classConstructor(){
    Java.perform(function() {
        let com_xiaofeng_Demo = Java.use("com.xiaofeng.Demo");
        
        // 修改类的构造函数的实现，$init表示类的构造函数
        com_xiaofeng_Demo["$init"].overload('java.lang.String').implementation = function(str){
            console.log(`[->] com_xiaofeng_Demo.$init is called! args are as follows:\n    ->str= ${str}`);
            var retval = this["$init"](str);
            console.log(`[<-] com_xiaofeng_Demo.$init ended! \n    retval= ${retval}`);
            return retval;
        };
    });
    console.warn(`[*] hook_classConstructor is injected!`);
};
hook_classConstructor();
