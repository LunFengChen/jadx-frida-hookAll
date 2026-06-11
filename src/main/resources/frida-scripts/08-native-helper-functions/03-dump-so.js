/* 这里推荐使用yang神的一键dump+自动修复脚本
 git clone https://github.com/lasting-yang/frida_dump
 cd frida_dump
 python dump_so.py libxxx.so
*/

/*
 * Dump SO 文件到 App 私有目录目录
 * 自动获取 SO 的基地址和大小信息
 * ? 为什么有了一键dump脚本还要自己搞呢，因为有的so会被多次加载然后我们dump的时机可能会有问题，所以要监控so加载然后dump
*/
// 统计全局 dump 了几个 so，防止同名的 so 被覆盖
var dump_num = 1;

function dump_so(so_name) {
    console.warn(`[*] ========== Dumping ${so_name} ... ========== `);
    // 获取模块信息
    var libso = Process.getModuleByName(so_name);

    // 处理权限问题
    var packageName = Java.use("android.app.ActivityThread").currentApplication().getPackageName();
    var file_path = "/data/data/" + packageName + "/cache/" + libso.name + "_" + libso.base + "_" + ptr(libso.size) + "_" + dump_num + ".so";
    Memory.protect(ptr(libso.base), libso.size, "rwx");
    
    // 读取 SO 内存
    var libso_buffer = ptr(libso.base).readByteArray(libso.size);
    
    // 创建文件并写入
    var f = new File(file_path, "wb");
    f.write(libso_buffer);
    f.close();
    
    console.log("[dump]:", file_path);
    
    dump_num++;
    console.warn(`[*] ========== Dump ${so_name} completely ========== `);
}


function monitor_and_dump_so(so_name) {
    Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"), {
        onEnter: function (args) {
            this.fileName = args[0].readCString();
            console.log(`[+] dlopen onEnter ==> ${this.fileName}`);
            if (this.fileName && this.fileName.includes(so_name)) {
                console.warn(`[+] dlopen onEnter ==> ${this.fileName}`);
                this.match = true;
            }
        },
        onLeave: function (retval) {
            if (this.match) {
                dump_so(so_name);
            }
        }
    });
    console.warn("[*] hook_dlopen is injected!");
}

// monitor_and_dump_so("libxxx.so");

/*
 * dump步骤：
 * attach:
 *      1. 代码 copy 进入 frida 控制台
 *      2. 调用函数 dump 指定 so
 *          dump_so("libxxx.so")
 * spawn:
 *      1. 取消注释 monitor_and_dump_so 调用
 *      2. frida -U -f <包名> -l xxx.js

 * 拉取/修复 步骤：
 * 1. 文件保存到 /sdcard/Download/ 目录，拉取
 *    adb shell su -c "cp /data/data/<包名>/cache/libxxx.so /sdcard/Download/"
 *    adb pull /sdcard/Download/libxxx.so
 * 
 * 2. 使用 SoFixer 修复 SO（根据架构选择 32/64 位）(这里也可以传入linux版本的，然后在手机修复好拿出来)
 *    .\SoFixer64-Windows.exe -m <基地址> -s <待修复so文件路径> -o <修复后so文件路径>
 * 
 * 优点：
 * - 监控so加载并自动 dump，解决dump时机问题 
 * - 设置 dump 次数，防止so多次加载被 后面的 被覆盖
 */
