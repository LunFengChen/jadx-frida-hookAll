// 功能：获取当前线程的调用栈
function showJavaStacks() {
    console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
}

// 注意事项：
// 1. 如果你遇到了$匿名类，在jadx搜索时请换成.  例如：com.example.app$a->com.example.app.a
// 2. Exception可以换成Throwable
// 3. 没事不要打开这个，会打印出一大堆信息；如果是给ai分析日志，全部打开，ai会帮你分析调用栈

// 使用示例:
// function hook_monitor_calcSignature(){
//     Java.perform(function () {
//         let com_iget_baselib_BaseApi = Java.use("com.iget.baselib.BaseApi");
//         com_iget_baselib_BaseApi["calcSignature"].implementation = function (map, map2) {
//             console.log(`[->] com_iget_baselib_BaseApi.calcSignature is called! args are as follows:\n    ->map= ${map}\n    ->map2= ${map2}`);
//             var retval = this["calcSignature"](map, map2);
//             // showJavaStacks(); // 打印调用栈
//             console.log(`[<-] com_iget_baselib_BaseApi.calcSignature ended! \n    retval= ${retval}`);
//             return retval;
//         };
//     });
//     console.warn(`[*] hook_monitor_calcSignature is injected!`);
// };
// hook_monitor_calcSignature();


/*
关于 堆栈打印 (Stack Trace) 的详解

原理：
利用 Java 异常机制。当创建一个 Exception 对象时，JVM 会自动填充当前的调用栈信息。
`Log.getStackTraceString(new Exception())` 是 Android 官方推荐的获取完整堆栈字符串的方法。

逆向价值：
1. 溯源：
   - 找到了关键函数（如加密函数），想知道是谁调用了它？
   - 打印堆栈可以向上追溯调用链，一直找到业务逻辑的起点（如按钮点击事件）。

2. 过滤干扰：
   - 有时候同一个函数被多处调用，通过判断堆栈内容，可以过滤掉无关的调用。
   - 例如：`if (stack.includes("com.example.ui.LoginActivity")) { ... }`

速记：
1. 想要知道“我是谁？我在哪？谁调用的我？”，就用这个。
2. 堆栈信息通常是从上往下看，第一行是当前函数，下面是调用者。
*/

