/**
 * 【功能】Dex 内存脱壳 - 基于 DexCache 枚举
 * 
 * 【参考】脚本hook点参考 https://github.com/lasting-yang/frida_dump(记得给原项目star)
 * 
 * 【原理】
 * Android Runtime (ART) 为了性能优化，会将已加载的 Dex 文件缓存在内存中的 java.lang.DexCache 对象里。
 * 每个被加载的 Dex 都对应一个 DexCache 实例，其中包含：
 *   - dexFile: Native 层的 art::DexFile 对象指针
 *   - location: Dex 文件路径（如 /data/app/xxx/base.apk）
 * 
 * 关键突破点：
 *   即使 Dex 被加固壳加密，当它被 ART 加载执行后，内存中的 DexCache.dexFile 指向的就是解密后的原始 Dex 数据！
 *   我们只需要：
 *     1. 枚举堆中所有 DexCache 实例
 *     2. 读取 dexFile 字段的 Native 指针
 *     3. 根据 art::DexFile 的 C++ 内存布局，计算出 Dex 数据的起始地址和大小
 *     4. 直接从内存复制完整 Dex 到磁盘
 * 
 * 【art::DexFile 内存布局】(64位系统示例)
 * struct DexFile {
 *   void* vtable_;            // 偏移 0x00: 虚函数表指针
 *   const uint8_t* begin_;    // 偏移 0x08: Dex 数据起始地址 ← 我们要的
 *   size_t size_;             // 偏移 0x10: Dex 文件大小 ← 我们要的
 *   std::string location_;    // 偏移 0x18: 文件路径
 *   ...
 * }
 * 
 * 【Dex 文件头结构】
 * offset 0x00: Magic Header ("dex\n035" 或 "dex\n037" 或 "dex\n038")
 * offset 0x20: file_size (4 bytes) - Dex 文件总大小
 * offset 0x24: header_size (4 bytes) - 固定为 0x70
 * 
 * 【适用场景】
 * ✅ 梆梆加固 / 360加固 / 爱加密 / 腾讯乐固等壳的脱壳
 * ✅ 动态加载的 Plugin Dex (插件化框架如 VirtualApp、DroidPlugin)
 * ✅ 热更新框架的 Patch Dex (Tinker、Robust、Sophix)
 * ✅ MultiDex 应用的全部 Dex (classes.dex, classes2.dex, ...)
 * ⚠️ VMP 虚拟机保护：如果关键代码被 VMP，Dex 可能不完整，需结合其他工具
 * ❌ Flutter / React Native：不使用 Dex，此脚本无效
 * 
 * 【逆向价值】
 * - 这是脱壳的首选方案，几乎所有加固壳都需要在运行时解密 Dex，此时内存中必然存在明文
 * - 获取完整 Dex 后，可用 jadx/JEB/GDA 反编译，查看源码
 * - 结合 frida-dexdump 等工具，可实现自动化批量脱壳
 * - 对于混淆代码，配合 frida hook 可动态分析执行流程
 * 
 */

Java.perform(function() {
    
    /**
     * 获取当前进程的包名
     * 通过读取 /proc/self/cmdline 文件（Linux 进程信息）
     * @returns {string} 包名，如 "com.example.app"
     */
    function getPackageName() {
        var openPtr = Module.getExportByName('libc.so', 'open');
        var readPtr = Module.getExportByName('libc.so', 'read');
        var closePtr = Module.getExportByName('libc.so', 'close');
        
        var open = new NativeFunction(openPtr, 'int', ['pointer', 'int']);
        var read = new NativeFunction(readPtr, 'int', ['int', 'pointer', 'int']);
        var close = new NativeFunction(closePtr, 'int', ['int']);
        
        var path = Memory.allocUtf8String("/proc/self/cmdline");
        var fd = open(path, 0);
        
        if (fd !== -1) {
            var buffer = Memory.alloc(0x1000);
            var result = read(fd, buffer, 0x1000);
            close(fd);
            
            if (result > 0) {
                return ptr(buffer).readCString();
            }
        }
        
        console.log("[!] 无法读取包名，使用默认值");
        return "unknown.app";
    }
    
    /**
     * 创建目录（递归）
     * 使用 libc.so 的 mkdir 系统调用，避免依赖 Java API
     * @param {string} path - 要创建的目录路径
     */
    function mkdirRecursive(path) {
        var mkdirPtr = Module.getExportByName('libc.so', 'mkdir');
        var opendirPtr = Module.getExportByName('libc.so', 'opendir');
        var closedirPtr = Module.getExportByName('libc.so', 'closedir');
        var chmodPtr = Module.getExportByName('libc.so', 'chmod');
        
        var mkdir = new NativeFunction(mkdirPtr, 'int', ['pointer', 'int']);
        var opendir = new NativeFunction(opendirPtr, 'pointer', ['pointer']);
        var closedir = new NativeFunction(closedirPtr, 'int', ['pointer']);
        var chmod = new NativeFunction(chmodPtr, 'int', ['pointer', 'int']);
        
        var cPath = Memory.allocUtf8String(path);
        
        // 检查目录是否已存在
        var dir = opendir(cPath);
        if (dir.toInt32() !== 0) {
            closedir(dir);
            return;
        }
        
        // 创建目录并设置权限 (0755 = rwxr-xr-x)
        mkdir(cPath, parseInt('0755', 8));
        chmod(cPath, parseInt('0755', 8));
        
        console.log("[+] 创建目录: " + path);
    }
    
    /**
     * 保存 Dex 文件到磁盘
     * @param {NativePointer} dexPtr - Dex 数据在内存中的起始地址
     * @param {number} dexSize - Dex 文件大小
     * @param {string} outputPath - 输出文件路径
     * @returns {boolean} 是否成功保存
     */
    function saveDex(dexPtr, dexSize, outputPath) {
        try {
            // 校验 Magic Header
            var magic = dexPtr.readCString(8);
            if (!magic || magic.indexOf("dex\n") !== 0) {
                console.log("[-] 无效的 Dex Magic: " + magic);
                return false;
            }
            
            // 校验 Header Size (offset 0x24, 固定为 0x70)
            var headerSize = dexPtr.add(0x24).readU32();
            if (headerSize !== 0x70) {
                console.log("[-] 异常的 Header Size: 0x" + headerSize.toString(16));
                return false;
            }
            
            // 读取文件大小字段（offset 0x20）并与传入的大小对比
            var fileSizeInHeader = dexPtr.add(0x20).readU32();
            if (fileSizeInHeader !== dexSize) {
                console.log("[!] 大小不匹配 - Header: " + fileSizeInHeader + ", 实际: " + dexSize);
                // 使用 Header 中的大小（更准确）
                dexSize = fileSizeInHeader;
            }
            
            // 读取内存数据
            var dexBuffer = dexPtr.readByteArray(dexSize);
            
            // 保存到文件
            var file = new File(outputPath, "wb");
            file.write(dexBuffer);
            file.flush();
            file.close();
            
            console.log("[√] Dump 成功: " + outputPath + " (大小: " + dexSize + " 字节, Magic: " + magic.trim() + ")");
            return true;
            
        } catch (e) {
            console.log("[×] 保存失败: " + e.message);
            return false;
        }
    }
    
    /**
     * 主函数：枚举 DexCache 并 Dump 所有 Dex
     */
    function dumpAllDex() {
        console.log("\n========== 开始 Dex 脱壳 ==========");
        
        var packageName = getPackageName();
        console.log("[*] 包名: " + packageName);
        
        // 创建输出目录（带时间戳，避免覆盖）
        var timestamp = new Date().toISOString().replace(/[:.]/g, '-').substring(0, 19);
        var outputDir = "/sdcard/Download/dump_dex_" + timestamp;
        mkdirRecursive(outputDir);
        
        var dexCount = 0;
        var dumpedSet = {}; // 用于去重（避免重复 Dump 同一个 Dex）
        
        // 枚举所有 DexCache 实例
        Java.choose("java.lang.DexCache", {
            onMatch: function(instance) {
                try {
                    // 获取 dexFile 字段（这是一个 long 类型，实际上是 art::DexFile* 指针）
                    var dexFile = instance.dexFile.value;
                    
                    if (!dexFile || dexFile === 0) {
                        return;
                    }
                    
                    // 去重检查
                    if (dumpedSet[dexFile]) {
                        return;
                    }
                    dumpedSet[dexFile] = true;
                    
                    /**
                     * art::DexFile 的内存布局解析：
                     * [偏移 0x00] void* vtable_
                     * [偏移 0x08] const uint8_t* begin_  ← Dex 数据起始地址（64位系统）
                     * [偏移 0x10] size_t size_          ← Dex 文件大小（64位系统）
                     * 
                     * 对于 32 位系统：
                     * [偏移 0x00] void* vtable_
                     * [偏移 0x04] const uint8_t* begin_
                     * [偏移 0x08] size_t size_
                     */
                    
                    var dexFilePtr = ptr(dexFile);
                    
                    // 读取 begin_ 指针（跳过 vtable，偏移量 = 指针大小）
                    var dexBegin = dexFilePtr.add(Process.pointerSize).readPointer();
                    
                    // 读取 size_ 字段（偏移量 = 2 * 指针大小）
                    var dexSize = dexFilePtr.add(Process.pointerSize * 2).readU32();
                    
                    if (!dexBegin || dexBegin.isNull() || dexSize === 0) {
                        return;
                    }
                    
                    dexCount++;
                    
                    // 生成文件名（与原始 APK 命名一致）
                    var fileName = "classes" + (dexCount === 1 ? "" : dexCount) + ".dex";
                    var outputPath = outputDir + "/" + fileName;
                    
                    console.log("\n[" + dexCount + "] 发现 Dex:");
                    console.log("    - DexFile 对象: " + dexFilePtr);
                    console.log("    - 内存地址: " + dexBegin);
                    console.log("    - 大小: " + dexSize + " bytes");
                    
                    // 尝试读取 location 字段（用于调试）
                    try {
                        var location = instance.location.value;
                        if (location) {
                            console.log("    - 来源: " + location);
                        }
                    } catch (e) {
                        // 某些 Android 版本可能没有 location 字段
                    }
                    
                    // 保存 Dex
                    saveDex(dexBegin, dexSize, outputPath);
                    
                } catch (e) {
                    console.log("[!] 处理 DexCache 时出错: " + e.message);
                }
            },
            onComplete: function() {
                console.log("\n========== 脱壳完成 ==========");
                console.log("[*] 共 Dump " + dexCount + " 个 Dex 文件");
                console.log("[*] 输出目录: " + outputDir);
                console.log("[*] 拉取命令: adb pull " + outputDir + " .");
                console.log("================================\n");
            }
        });
    }
    
    // 延迟 3 秒执行，确保 App 完成初始化
    setTimeout(function() {
        dumpAllDex();
    }, 3000);
    
});
