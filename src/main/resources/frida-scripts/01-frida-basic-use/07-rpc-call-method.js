/*
 * 主动调用方法 - RPC 方式
 * 通过 Frida RPC 机制主动调用 Java 方法，适用于测试、调试场景
 * 
 * 使用步骤：
 * 1. 修改函数名、类名、参数
 * 2. frida -U -f com.package.name -l script.js
 * 3. Python 端调用: script.exports.call_target_method()
 */

// 导出 RPC 接口
rpc.exports = {
    callTargetMethod: function() {
        return call_target_method();
    }
};

/**
 * 主动调用目标方法
 * @returns {string} 方法返回值
 */
function call_target_method() {
    return Java.perform(function () {
        try {
            // 1. 获取目标类
            // 示例: com.max.xiaoheihe.utils.NDKTools
            let TargetClass = Java.use("com.example.TargetClass");
            
            // 2. 准备参数 (根据实际方法签名修改)
            // 提示: 可以先 Hook 目标方法，观察参数类型和示例值
            
            // 示例 1: 简单类型参数
            var arg1 = "test_string";
            var arg2 = 12345;
            
            // 示例 2: 对象参数
            // var arg1_obj = Java.use("android.content.Context").$new();
            
            // 示例 3: null 参数
            // var arg1 = Java.use("java.lang.Object").$new();
            
            // 3. 调用方法
            // 方法签名示例: targetMethod(Ljava/lang/String;I)Ljava/lang/String;
            var retval = TargetClass["targetMethod"](arg1, arg2);
            
            // 4. 打印结果
            console.log("[*] ========== RPC Call Result ==========");
            console.log("[*] Class: " + TargetClass.$className);
            console.log("[*] Method: targetMethod");
            console.log("[*] Args: [" + arg1 + ", " + arg2 + "]");
            console.log("[*] Return: " + retval);
            console.log("[*] ======================================");
            
            return retval;
            
        } catch (error) {
            console.error("[!] Error calling method: " + error);
            console.error("[!] Stack: " + error.stack);
            return null;
        }
    });
}

/*
 * 使用示例 (Python 端):
 * 
 * import frida, sys
 * 
 * def on_message(message, data):
 *     print(message)
 * 
 * device = frida.get_usb_device()
 * pid = device.spawn(["com.example.app"])
 * session = device.attach(pid)
 * 
 * with open("script.js") as f:
 *     script = session.create_script(f.read())
 * 
 * script.on('message', on_message)
 * script.load()
 * device.resume(pid)
 * 
 * # 等待应用启动
 * import time
 * time.sleep(3)
 * 
 * # 调用 RPC 方法
 * result = script.exports.call_target_method()
 * print("Result:", result)
 */

/*
 * 完整示例 - 模拟真实场景:
 * 
 * rpc.exports = {
 *     callGetrsakey: function() {
 *         return call_getrsakey();
 *     }
 * };
 * 
 * function call_getrsakey(){
 *     return Java.perform(function () {
 *         // Smali signature: getrsakey(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
 *         let NDKTools = Java.use("com.max.xiaoheihe.utils.NDKTools");
 *         
 *         // 准备参数 (建议先 Hook 该方法，观察真实参数)
 *         var arg1_obj = Java.use("android.app.Application").$new();
 *         var arg2_str = "test_key";
 *         var arg3_str = "test_value";
 * 
 *         var retval = NDKTools["getrsakey"](arg1_obj, arg2_str, arg3_str);
 *         console.warn(`[*] NDKTools.getrsakey is called! \nretval= ${retval}`);
 *         return retval;
 *     });
 * }
 */
