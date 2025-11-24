// Monitor File operations (read/write)
// 监控文件读写操作
// java.io.File / java.io.FileOutputStream / java.io.FileInputStream: Java标准文件操作类。
// 用途：文件的创建、写入、读取。
// 逆向价值：**中等偏高**。
//           1. 写入(FileOutputStream): 监控App在本地创建了哪些文件（如数据库、配置文件、缓存图片）。
//           2. 读取(FileInputStream): 监控App读取了哪些敏感文件（如读取 /proc/self/maps 检测Frida，或读取本地密钥文件）。
function hook_monitor_file() {
    Java.perform(function () {
        // Helper function to print stack trace
        function showJavaStacks() {
            console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        }

        let java_io_FileOutputStream = Java.use("java.io.FileOutputStream");
        let java_io_FileInputStream = Java.use("java.io.FileInputStream");
        let java_io_File = Java.use("java.io.File");

        // 1. 监控 FileOutputStream 构造函数 (File) - 写文件
        java_io_FileOutputStream["$init"].overload("java.io.File").implementation = function (file) {
            let file_path = file.getAbsolutePath();
            console.log(`[->] java_io_FileOutputStream.$init(File) [WRITE]`);
            console.log(`    ->file= ${file_path}`);
            showJavaStacks();
            var retval = this["$init"](file);
            return retval;
        };

        // 2. 监控 FileOutputStream 构造函数 (String) - 写文件
        java_io_FileOutputStream["$init"].overload("java.lang.String").implementation = function (file_path) {
            console.log(`[->] java_io_FileOutputStream.$init(String) [WRITE]`);
            console.log(`    ->file_path= ${file_path}`);
            showJavaStacks();
            var retval = this["$init"](file_path);
            return retval;
        };
        
        // 3. 监控 FileInputStream 构造函数 (File) - 读文件
        // 逆向场景：非常重要。App启动时读取配置文件、证书、或检测系统文件(如 /system/bin/su)。
        java_io_FileInputStream["$init"].overload("java.io.File").implementation = function (file) {
            let file_path = file.getAbsolutePath();
            console.log(`[->] java_io_FileInputStream.$init(File) [READ]`);
            console.log(`    ->file= ${file_path}`);
            showJavaStacks();
            var retval = this["$init"](file);
            return retval;
        };

        // 4. 监控 FileInputStream 构造函数 (String) - 读文件
        java_io_FileInputStream["$init"].overload("java.lang.String").implementation = function (file_path) {
            console.log(`[->] java_io_FileInputStream.$init(String) [READ]`);
            console.log(`    ->file_path= ${file_path}`);
            showJavaStacks();
            var retval = this["$init"](file_path);
            return retval;
        };
        
        // 5. 监控 File.delete
        // 作用: 删除文件。
        // 逆向场景：监控App的自清理行为，或者反调试（删除特征文件）。
        java_io_File["delete"].implementation = function() {
            let path = this.getAbsolutePath();
            let result = this["delete"]();
            console.log(`[->] java_io_File.delete is called!`);
            console.log(`    ->path= ${path}`);
            console.log(`    ->result= ${result}`);
            showJavaStacks();
            return result;
        }
    });
    console.warn(`[*] hook_monitor_file is injected!`);
};
hook_monitor_file();
