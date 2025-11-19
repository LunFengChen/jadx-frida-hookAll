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

