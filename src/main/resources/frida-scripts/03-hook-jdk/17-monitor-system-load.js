// Monitor System.loadLibrary / System.load
// 监控 SO 库加载
// java.lang.System.loadLibrary / java.lang.Runtime.loadLibrary
// 用途：加载 Native 库 (.so 文件)。
// 逆向价值：**极高**。
//           1. 确定核心逻辑所在的 SO 库名称。
//           2. 确定 SO 库的加载时机（Hook JNI_OnLoad 的前提）。
//           3. 监控动态下发的 SO 库加载（插件化/热更新）。
function hook_monitor_system_load() {
    Java.perform(function () {
        // Helper function to print stack trace
        function showJavaStacks() {
            console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        }

        let java_lang_System = Java.use("java.lang.System");
        let java_lang_Runtime = Java.use("java.lang.Runtime");

        // 1. System.loadLibrary(String libname)
        // 加载已安装在系统路径或 App 库路径下的 SO
        // 参数是库名，例如 "native-lib" (对应 libnative-lib.so)
        java_lang_System["loadLibrary"].implementation = function (libname) {
            console.log(`\n[->] java_lang_System.loadLibrary() is called!`);
            console.log(`    ->libname= ${libname}`);
            showJavaStacks();
            return this["loadLibrary"](libname);
        };

        // 2. System.load(String filename)
        // 加载指定绝对路径的 SO
        // 参数是完整路径，例如 "/data/data/com.example/files/libhack.so"
        java_lang_System["load"].implementation = function (filename) {
            console.log(`\n[->] java_lang_System.load() is called!`);
            console.log(`    ->filename= ${filename}`);
            showJavaStacks();
            return this["load"](filename);
        };

        // 3. Runtime.loadLibrary (System.loadLibrary 最终也会调用这个)
        // 有时候直接 Hook Runtime 会更底层一些
        java_lang_Runtime["loadLibrary"].overload('java.lang.String', 'java.lang.ClassLoader').implementation = function (libname, classLoader) {
            console.log(`\n[->] java_lang_Runtime.loadLibrary() is called!`);
            console.log(`    ->libname= ${libname}`);
            console.log(`    ->classLoader= ${classLoader}`);
            // showJavaStacks();
            return this["loadLibrary"](libname, classLoader);
        };

        // 4. Runtime.load
        java_lang_Runtime["load"].overload('java.lang.String', 'java.lang.ClassLoader').implementation = function (filename, classLoader) {
            console.log(`\n[->] java_lang_Runtime.load() is called!`);
            console.log(`    ->filename= ${filename}`);
            console.log(`    ->classLoader= ${classLoader}`);
            // showJavaStacks();
            return this["load"](filename, classLoader);
        };
    });
    console.warn(`[*] hook_monitor_system_load is injected!`);
}
hook_monitor_system_load();
