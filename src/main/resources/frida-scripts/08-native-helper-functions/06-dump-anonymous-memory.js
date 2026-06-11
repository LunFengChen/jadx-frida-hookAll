/*
 * Dump 匿名内存到文件
 * 用于 dump 没有模块名称的内存区域（如动态解密的 DEX、SO 等）
 * 
 * 使用方法：
 * 1. 通过 Memory.enumerateRanges() 或其他方式找到目标内存地址和大小
 * 2. 调用 dump_anonymous_memory(0x12345678, 0x10000)
 * 3. 文件会保存到/sdcard/Download，然后 adb pull 出来
 */


function dump_anonymous_memory(address_base, module_size) {
        console.warn(`[*] ========== Dumping anonymous memory ... ========== `);
        // 解析地址和大小
        var base = ptr(address_base);
        var size = parseInt(module_size);

        // 构造文件名：anon_<基地址>_<大小>_<序号>.bin
        var file_path = "/sdcard/Download/anon_" + base + "_" + size + ".bin";

        // 创建文件
        var file_handle = new File(file_path, "wb");
        if (file_handle && file_handle != null) {
            // 修改内存保护为可读
            Memory.protect(base, size, "rwx");

            // 读取内存
            var memory_buffer = base.readByteArray(size);

            // 写入文件
            file_handle.write(memory_buffer);
            file_handle.flush();
            file_handle.close();

            console.log("[dump]:", file_path);
        } else {
            console.error("[!] Failed to create file!");
        }

        console.warn(`[*] ========== Dump anonymous memory completely ========== `);
}
/*
 * 使用步骤：
 * 
 * 1. 代码 copy 进入 frida 控制台
 * 2. 调用函数（地址和大小根据实际情况修改）
 *    dump_anonymous_memory(0x7b12345000, 0x100000)
 * 
 * 3. 复制 dump 的文件路径
 *    adb shell
 *    su
 * 
 * 4. 下载文件
 *    adb pull /sdcard/Download/anon_*.bin
 * 
 * 5. 根据需要使用 IDA 等工具分析二进制文件
 */