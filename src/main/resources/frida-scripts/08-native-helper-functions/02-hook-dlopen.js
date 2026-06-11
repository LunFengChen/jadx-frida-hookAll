/*
 * Hook dlopen - 监控 SO 加载
 * 监控动态库加载过程，可用于分析加固、反调试等场景
 */

function hook_dlopen(targetSoName) {
    // dlopen主要是 hook native函数中加载别的so的，典型的如加固或者系统级别的so；
    Interceptor.attach(Module.findExportByName(null, "dlopen"), {
        onEnter: function (args) {
            this.fileName = args[0].readCString();
            console.log(`[+] dlopen onEnter ==> ${this.fileName}`);
            if (!targetSoName || this.fileName.indexOf(targetSoName) >= 0) {
                this.isMatch = true;
            }
        },
        onLeave: function (retval) {
            console.log(`[-] dlopen onLeave <== ${this.fileName}`);
            if (this.isMatch) {
                let address_JNI_OnLoad = Module.getExportByName(this.fileName, 'JNI_OnLoad');
                console.warn(`[*] found JNI_OnLoad in ${this.fileName}, address is at ${address_JNI_OnLoad}`);
            }
        }   
    });
    // android_dlopen_ext，现在一般都用这个；因为system.loadlibrary/load底层就是调用这个函数的；还有native层有的也会引入这个导出函数然后调用；
    // 详细源码分析请看: https://t.zsxq.com/BSZKj
    Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"), {
        onEnter: function (args) {
            this.fileName = args[0].readCString();
            console.log(`[+] dlopen onEnter ==> ${this.fileName}`);

            if (!targetSoName || this.fileName.indexOf(targetSoName) >= 0) {
                this.isMatch = true;
            }
        }, 
        onLeave: function (retval) {
            console.log(`[-] dlopen onLeave <== ${this.fileName}`);

            // 对匹配的 SO 进行详细监控
            if (this.isMatch) {
                let address_JNI_OnLoad = Module.getExportByName(this.fileName, 'JNI_OnLoad');
                console.warn(`[*] found JNI_OnLoad in ${this.fileName}, address is at ${address_JNI_OnLoad}`);
            }
        }
    });
}

// 启动 Hook
// hook_dlopen();
// hook_dlopen("libdexprotector.so");

/*
 * 使用说明：
 * 
 * 1. 监控所有 SO 的加载（不指定目标）
 *    hook_dlopen();
 * 
 * 2. 默认监控所有so， 目标so监控JNI_OnLoad
 *    hook_dlopen("libdexprotector.so");
 * 
 * 3. 运行脚本
 *    frida -U -f com.example.app -l hook_dlopen.js
 * 
 * 应用场景：
 * - 监控加固 SO 的加载时机
 * - Hook SO 的 JNI_OnLoad 初始化函数
 * - 分析 SO 加载顺序和依赖关系
 * - 在 SO 加载后立即进行 Hook 或 Dump
 * 
 * 注意事项：
 * - 如果不传参数，会监控所有 SO 并尝试 Hook 所有 JNI_OnLoad
 * - 建议先不传参数观察所有 SO，再针对目标 SO 进行监控
 */
