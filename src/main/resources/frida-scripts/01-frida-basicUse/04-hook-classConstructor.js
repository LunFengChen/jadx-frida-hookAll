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

/*
关于 Hook 构造函数 ($init) 的详解

在 Java 字节码和 Frida 中，构造函数有一个特殊的名字：`$init`。

关键点：
1. 实例构造函数：
   - 名字：`$init`
   - 对应 Java 代码：`public ClassName(...) { ... }`
   - 每个 `new ClassName(...)` 操作都会调用它。
   - 必须使用 `implementation` 进行 Hook。
   - 必须在 `implementation` 内部调用 `this.$init(...)` (除非你想阻止对象初始化，但这通常会导致崩溃)。

2. 静态初始化块 (Static Initializer)：
   - 名字：`$clinit` (Class Init)
   - 对应 Java 代码：`static { ... }`
   - 在类第一次被加载时执行，只执行一次。
   - Frida 不太容易 Hook `$clinit`，因为它通常在 `Java.use` 之前就已经执行完了。
   - 除非你在类加载之前就拦截到（比较高级的操作）。

速记：
1. 构造函数就是 `$init`。
2. 不要忘了 `$init` 也可以重载 (.overload)。
3. Hook 构造函数是监控对象创建的最佳位置（例如监控 File 对象创建路径、URL 对象创建链接）。
*/
