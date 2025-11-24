// 枚举所有已加载的类与类的方法
function hook_enumerateClasses(){
    Java.perform(function(){
        // 枚举所有的类与类的所有方法,异步枚举
        Java.enumerateLoadedClasses({
            onMatch: function(name, handle){
                // 过滤类名
                if(name.indexOf("com.xiaofeng.Demo") != -1){
                    console.log("Found class:", name);
                    let loadedClass = Java.use(name);
                    console.log("Class object:", loadedClass);
                    let methods = loadedClass.class.getDeclaredMethods();
                    console.log("Methods:", methods);
                }
            },
            onComplete: function(){
                console.log("Enumeration completed");
            }
        })
    })
    console.warn(`[*] hook_enumerateClasses is injected!`);
};
hook_enumerateClasses();

/*
关于 枚举类 (Enumeration) 的详解

在逆向分析中，我们经常需要找“某个包下有哪些类”或者“某个类有哪些方法”。

核心 API：
1. Java.enumerateLoadedClasses(callbacks)
   - 作用：枚举当前内存中**已经加载**的所有类。
   - 注意：如果类还没被加载（即 App 还没运行到那部分代码），这里是搜不到的。
   - 解决：如果搜不到，可以手动尝试 `Java.use("ClassName")` 触发加载，或者在合适的时机（如 Application.attachBaseContext）再枚举。

2. 反射获取方法 (Reflection)
   - Frida 的 `Java.use(name)` 得到的是 JS 包装对象。
   - 访问 `.class` 属性可以拿到原生的 `java.lang.Class` 对象。
   - 进而调用反射 API：
     - `getDeclaredMethods()`: 获取所有声明的方法（包括私有，不包括继承）。
     - `getMethods()`: 获取所有公有方法（包括继承）。
     - `getDeclaredFields()`: 获取所有字段。

速记：
1. 找不到类？可能是还没加载，或者是被 Dex 加固隐藏了。
2. 想要打印类的所有方法？直接用脚本里的反射写法，比手动去翻 smali 快得多。
3. `onMatch` 回调里不要做太耗时的操作，否则会卡死 App。
*/
