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

/*
关于 SO 加载 (System.loadLibrary) 的详解

Java 层加载 Native 动态库 (.so) 的标准方式。

核心方法：
1. System.loadLibrary("name"):
   - 传入库的短名称（不带前缀 lib 和后缀 .so）。
   - 系统会自动去 `java.library.path` (通常是 `/data/app/包名/lib/arm64`) 寻找 `libname.so`。

2. System.load("/path/to/libname.so"):
   - 传入 SO 文件的绝对路径。
   - 常用于插件化加载、热修复、或者加载解密后释放到临时目录的 SO。

逆向价值：
1. 找核心算法：
   - 如果看到 `loadLibrary("encode")`，那加密逻辑大概率在 `libencode.so` 里。
   - 此时可以去 IDA 里分析这个 SO。

2. Hook JNI_OnLoad：
   - SO 加载后，系统会立即调用其导出的 `JNI_OnLoad` 函数（如果存在）。
   - 这是 Native 层的入口点，常用于动态注册 JNI 函数。
   - 我们可以在 Hook 到 `loadLibrary` 之后，利用 Frida 的 `Module.load` 或 `Process.findModuleByName` 进一步 Hook `JNI_OnLoad`。

速记：
1. `loadLibrary` 参数是名字，`load` 参数是路径。
2. 看到 `load("/data/user/0/.../lib.so")`，通常是动态加载（壳/插件）。
*/
