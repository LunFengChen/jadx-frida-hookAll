/**
 * =====================================================
 * 【功能】Dex 内存脱壳 - 基于 DefineClass Native Hook
 * =====================================================
 * 
 * 【致谢与参考】
 * 本脚本核心思路来源于开源项目：
 * 项目名称：frida_dump
 * 项目地址：https://github.com/lasting-yang/frida_dump
 * 原始文件：dump_dex.js
 * 
 * 本脚本在原项目基础上进行了优化和重写：
 *   - 添加了详细的中文注释（原理、版本适配、符号查找）
 *   - 增强了兼容性检测（符号未找到时的友好提示）
 *   - 改进了日志输出（显示触发类名、内存地址等）
 * 
 * 如果本脚本对你有帮助，请给原项目点个 ⭐ Star！
 * GitHub: https://github.com/lasting-yang/frida_dump
 * 
 * =====================================================
 * 
 * 【核心原理】
 * 在 Android Runtime (ART) 中，每个 Java 类被加载时都会调用 ClassLinker::DefineClass 函数。
 * 这是一个 Native 层的关键函数，负责：
 *   1. 解析 Dex 文件中的 ClassDef 结构
 *   2. 创建 mirror::Class 对象（Java 层的 Class 对象在 Native 的表示）
 *   3. 建立类与 DexFile 的关联
 * 
 * 函数原型（Android 9+ 为例）：
 * mirror::Class* ClassLinker::DefineClass(
 *     Thread* self,                        // args[0]
 *     const char* descriptor,              // args[1] - 类名，如 "Lcom/example/App;"
 *     size_t hash,                         // args[2]
 *     Handle<mirror::ClassLoader> loader,  // args[3]
 *     const DexFile& dex_file,            // args[4] - Dex 文件对象引用 ← 关键！
 *     const DexFile::ClassDef& class_def   // args[5]
 * );
 * 
 * 【关键突破点】
 * 参数 args[4] 是 const DexFile& 引用，指向当前类所在的 Dex 文件对象。
 * 通过 Hook 这个函数，我们能在"类加载的第一时间"拿到 Dex 的内存地址，甚至早于 DexCache 方式。
 * 
 * 【技术优势】
 * ✅ 捕获时机早：在类加载的瞬间就能拿到 Dex，适合分析 App 启动流程
 * ✅ 覆盖全面：所有被加载的类（包括系统类、第三方库类）都会触发
 * ✅ 动态加载感知：插件化、热更新加载的 Dex 也会被捕获
 * 
 * 【技术挑战】
 * ❌ 符号依赖：需要通过 C++ Name Mangling 后的符号名定位函数
 * ❌ 版本兼容性：不同 Android 版本的 DefineClass 签名可能变化
 * ❌ 参数偏移：args[] 数组的索引可能因编译器和架构而异
 * 
 * 【Android 版本适配】
 * | Android 版本 | 符号模式                                                        | 参数位置     |
 * |-------------|----------------------------------------------------------------|-------------|
 * | 7.x - 8.x   | _ZN3art11ClassLinker11DefineClassE...                          | args[4]     |
 * | 9.x - 10.x  | _ZN3art11ClassLinker11DefineClassEPNS_6ThreadE...DexFile...   | args[4]     |
 * | 11.x+       | 可能使用新的符号或内联优化                                         | 需测试      |
 * 
 * 【使用场景】
 * ✅ 分析壳的初始化流程（抓取壳 DEX 和原始 DEX 的加载顺序）
 * ✅ 插件化框架的 Dex 加载时机分析（如 VirtualApp）
 * ✅ 热更新 Patch 的加载监控（Tinker、Sophix）
 * ⚠️ 普通脱壳：推荐使用 01-dump-dex-cache.js（更稳定）
 * 
 * 【使用方法】
 * 1. 使用 frida-spawn 模式启动（确保在 libart.so 加载前注入）：
 *    frida -U -f com.example.app -l 02-dump-dex-defineclass.js --no-pause
 * 2. 观察日志，查看 Dex 的加载顺序和时机
 * 3. Dex 文件保存路径：/sdcard/Download/dump_dex_defineclass/
 * 
 * 【注意事项】
 * 1. 必须在 App 启动前注入（spawn 模式），否则 libart.so 已加载，Hook 会失败
 * 2. 某些壳会检测 Hook（如梆梆），可能触发反调试
 * 3. 高频调用：DefineClass 每加载一个类都会触发，日志量巨大，建议加过滤条件
 * 
 * 【逆向价值】
 * ★★★★☆ 适合深度分析加载流程，但稳定性不如 DexCache 方式
 * - 可以看到 Dex 的加载顺序（壳 DEX 先加载，原始 DEX 后加载）
 * - 结合类名过滤，可精准定位某个类所在的 Dex
 * - 对于研究壳的脱壳时机有重要价值
 * 
 * =====================================================
 */

// 辅助函数：获取包名
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
    
    return "unknown.app";
}

// 辅助函数：创建目录
function mkdirRecursive(path) {
    var mkdirPtr = Module.getExportByName('libc.so', 'mkdir');
    var chmodPtr = Module.getExportByName('libc.so', 'chmod');
    var opendirPtr = Module.getExportByName('libc.so', 'opendir');
    var closedirPtr = Module.getExportByName('libc.so', 'closedir');
    
    var mkdir = new NativeFunction(mkdirPtr, 'int', ['pointer', 'int']);
    var chmod = new NativeFunction(chmodPtr, 'int', ['pointer', 'int']);
    var opendir = new NativeFunction(opendirPtr, 'pointer', ['pointer']);
    var closedir = new NativeFunction(closedirPtr, 'int', ['pointer']);
    
    var cPath = Memory.allocUtf8String(path);
    var dir = opendir(cPath);
    
    if (dir.toInt32() !== 0) {
        closedir(dir);
        return;
    }
    
    mkdir(cPath, parseInt('0755', 8));
    chmod(cPath, parseInt('0755', 8));
}

// 辅助函数：保存 Dex
function saveDex(dexPtr, dexSize, outputPath) {
    try {
        var magic = dexPtr.readCString(8);
        if (!magic || magic.indexOf("dex\n") !== 0) {
            return false;
        }
        
        var dexBuffer = dexPtr.readByteArray(dexSize);
        var file = new File(outputPath, "wb");
        file.write(dexBuffer);
        file.flush();
        file.close();
        
        console.log("[√] Dump: " + outputPath + " (" + dexSize + " bytes, " + magic.trim() + ")");
        return true;
    } catch (e) {
        console.log("[×] 保存失败: " + e.message);
        return false;
    }
}

/**
 * 主函数：Hook DefineClass
 */
function hookDefineClass() {
    console.log("\n========== DefineClass Hook 脱壳 ==========");
    
    // 查找 libart.so
    var libart = Process.findModuleByName("libart.so");
    if (!libart) {
        console.log("[!] 未找到 libart.so，等待加载...");
        return;
    }
    
    console.log("[+] 找到 libart.so: " + libart.base);
    
    // 枚举符号，查找 DefineClass
    var symbols = libart.enumerateSymbols();
    var addrDefineClass = null;
    
    for (var i = 0; i < symbols.length; i++) {
        var symbol = symbols[i];
        var name = symbol.name;
        
        // 匹配符号：包含 ClassLinker、DefineClass、Thread、DexFile
        if (name.indexOf("ClassLinker") >= 0 &&
            name.indexOf("DefineClass") >= 0 &&
            name.indexOf("Thread") >= 0 &&
            name.indexOf("DexFile") >= 0) {
            
            addrDefineClass = symbol.address;
            console.log("[+] 找到 DefineClass: " + name);
            console.log("    地址: " + addrDefineClass);
            break;
        }
    }
    
    if (!addrDefineClass) {
        console.log("[!] 未找到 DefineClass 符号，可能不兼容当前 Android 版本");
        console.log("[!] 建议使用 01-dump-dex-cache.js 替代");
        return;
    }
    
    // 初始化
    var packageName = getPackageName();
    var outputDir = "/sdcard/Download/dump_dex_defineclass";
    mkdirRecursive(outputDir);
    
    var dexMap = {}; // 去重 Map (key: base, value: size)
    var dexCount = 0;
    
    // Hook DefineClass
    Interceptor.attach(addrDefineClass, {
        onEnter: function(args) {
            try {
                /**
                 * 参数解析（Android 9 为例）：
                 * args[0]: Thread* self
                 * args[1]: const char* descriptor（类名）
                 * args[2]: size_t hash
                 * args[3]: Handle<ClassLoader>
                 * args[4]: const DexFile& dex_file ← 我们要的
                 * args[5]: const ClassDef& class_def
                 * 
                 * 注意：在某些架构（如 ARM64）中，引用参数可能通过寄存器或栈传递
                 * 这里假设 args[4] 是 DexFile 对象的指针（实际是引用，C++ 引用底层就是指针）
                 */
                
                var dexFilePtr = ptr(args[4]);
                
                // DexFile 内存布局：
                // +0x00: vtable
                // +0x08: const uint8_t* begin_ (64位)
                // +0x10: size_t size_ (64位)
                var dexBegin = dexFilePtr.add(Process.pointerSize).readPointer();
                var dexSize = dexFilePtr.add(Process.pointerSize * 2).readU32();
                
                // 去重检查
                if (dexMap[dexBegin]) {
                    return;
                }
                dexMap[dexBegin] = dexSize;
                
                // 校验 Magic
                var magic = dexBegin.readCString(8);
                if (!magic || magic.indexOf("dex") !== 0) {
                    return;
                }
                
                dexCount++;
                
                // 读取类名（用于调试）
                var className = "unknown";
                try {
                    className = ptr(args[1]).readCString();
                } catch (e) {}
                
                // 生成文件名
                var fileName = "classes" + (dexCount === 1 ? "" : dexCount) + ".dex";
                var outputPath = outputDir + "/" + fileName;
                
                console.log("\n[" + dexCount + "] 发现 Dex (触发类: " + className + ")");
                console.log("    - 内存地址: " + dexBegin);
                console.log("    - 大小: " + dexSize + " bytes");
                
                saveDex(dexBegin, dexSize, outputPath);
                
            } catch (e) {
                console.log("[!] Hook 处理出错: " + e.message);
            }
        }
    });
    
    console.log("[*] Hook 已设置，开始监控类加载...\n");
}

// Hook dlopen，确保 libart.so 加载后立即 Hook
var isHooked = false;

Interceptor.attach(Module.findExportByName(null, "dlopen"), {
    onEnter: function(args) {
        var path = ptr(args[0]).readCString();
        if (path && path.indexOf("libart.so") >= 0) {
            this.shouldHook = true;
            console.log("[*] 检测到 libart.so 加载: " + path);
        }
    },
    onLeave: function(retval) {
        if (this.shouldHook && !isHooked) {
            hookDefineClass();
            isHooked = true;
        }
    }
});

// 兼容 Android 7+ 的 android_dlopen_ext
Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"), {
    onEnter: function(args) {
        var path = ptr(args[0]).readCString();
        if (path && path.indexOf("libart.so") >= 0) {
            this.shouldHook = true;
            console.log("[*] 检测到 libart.so 加载 (android_dlopen_ext): " + path);
        }
    },
    onLeave: function(retval) {
        if (this.shouldHook && !isHooked) {
            hookDefineClass();
            isHooked = true;
        }
    }
});

console.log("[*] 等待 libart.so 加载...");
