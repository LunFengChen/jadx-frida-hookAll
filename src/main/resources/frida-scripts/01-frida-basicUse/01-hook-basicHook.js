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

/*
关于 Frida 基础 Hook 的详解

1. Java.perform(function(){ ... })
   - 这是 Frida 进入 Java 运行时的入口。
   - 所有的 Java Hook 代码都必须包裹在这个函数中。
   - 它确保了当前线程已附加到 Java 虚拟机 (VM)。

2. Java.use("类名")
   - 获取 Java 类的包装对象 (Wrapper)。
   - 类似于 Java 反射中的 Class.forName()。
   - 类名必须是完整的包名+类名 (例如: "java.lang.String", "com.example.MainActivity")。

3. implementation
   - 核心 Hook 逻辑。
   - 通过赋值给 method.implementation 来替换原方法的实现。
   - 函数签名 (参数列表) 必须与原方法一致。

4. this
   - 在 implementation 函数内部，`this` 指向当前被调用的实例对象 (Instance)。
   - `this.method(a, b)` 用于调用原始方法（即执行原逻辑）。
   - 如果 Hook 的是静态方法 (static)，`this` 依然可用，但通常没有实例字段。

速记：
1. 只要 Hook Java，第一行必写 Java.perform。
2. 遇到类找不到，检查包名对不对，是不是在 DexClassLoader 加载的插件里。
3. 修改参数和返回值是利用hook 绕过检测，拦截调用 的基础操作。
*/