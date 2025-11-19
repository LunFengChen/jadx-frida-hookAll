// Monitor File operations (read/write)
// 监控文件读写操作
function showJavaStacks() {
    console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
}

function hook_monitor_file(){
    Java.perform(function(){
        var java_io_FileOutputStream = Java.use("java.io.FileOutputStream");
      
        java_io_FileOutputStream.$init.overload("java.io.File").implementation = function(file){
            var file_path = file.getAbsolutePath();
            console.warn(`生成文件: ${file_path}`);
            showJavaStacks();
            return this.$init(file);
        }
      
        java_io_FileOutputStream.$init.overload("java.lang.String").implementation = function(file_path){
            console.warn(`生成文件: ${file_path}`);
            showJavaStacks();
            return this.$init(file_path);
        }
    });
    console.warn("[*] hook_monitor_file is injected");
}

hook_monitor_file();
