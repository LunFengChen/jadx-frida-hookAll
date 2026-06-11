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

/*
关于 Hook 内部类 (Inner Class) 的详解

Java 编译后，内部类会变成独立的 class 文件，命名规则通常是 `外部类$内部类`。

常见类型：
1. 成员内部类 (Member Inner Class)：
   - 源码：class Outer { class Inner {} }
   - 类名：`Outer$Inner`

2. 静态内部类 (Static Nested Class)：
   - 源码：class Outer { static class Inner {} }
   - 类名：`Outer$Inner`

3. 匿名内部类 (Anonymous Inner Class) - 逆向最头疼的！
   - 源码：new Runnable() { ... }
   - 类名：`Outer$1`, `Outer$2` (按出现顺序自动编号)
   - 这种类通常混淆后难以分辨，需要结合 Jadx 的 smali 代码或者 "Use Source Name" 功能来确定具体的 $数字。

技巧：
- 如果你不确定内部类的名字，可以在 Jadx 里看 "ClassNode" 的 title。
- 或者在 Frida 中先 enumerateLoadedClasses 过滤出 `Outer$` 开头的所有类，打印出来看看。

速记：
1. 遇到内部类，用 `$` 连接外部类和内部类名。
2. 遇到 `$` 符号后面跟数字的 (如 `$1`), 那是匿名内部类。
*/
