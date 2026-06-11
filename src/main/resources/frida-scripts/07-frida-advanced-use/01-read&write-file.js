/**
 * 使用 Frida API 写文件（推荐方式）
 * @param {string} filepath - 文件路径
 * @param {string|ArrayBuffer} content - 写入内容（字符串或二进制数据）
 * @param {string} mode - 打开模式 "w"=覆盖写, "a"=追加, "wb"=二进制写
 * @returns {boolean} 是否成功
 */
function writeFileByFrida(filepath, content, mode) {
    try {
        var file = new File(filepath, mode || "w");
        file.write(content);
        file.flush();
        file.close();
        console.log("[+] 文件写入成功:", filepath);
        return true;
    } catch (e) {
        console.error("[-] 文件写入失败:", e);
        return false;
    }
}

/**
 * 使用 libc.so 函数写文件（支持字符串和二进制）
 * @param {string} filepath - 文件路径
 * @param {string|ArrayBuffer} content - 写入内容
 * @param {string} mode - 打开模式 "w"=覆盖, "a"=追加, "wb"=二进制
 * @returns {boolean} 是否成功
 */
function writeFileByLibc(filepath, content, mode) {
    try {
        var fopen = new NativeFunction(Module.findExportByName("libc.so", "fopen"), 
            "pointer", ["pointer", "pointer"]);
        var fwrite = new NativeFunction(Module.findExportByName("libc.so", "fwrite"), 
            "size_t", ["pointer", "size_t", "size_t", "pointer"]);
        var fclose = new NativeFunction(Module.findExportByName("libc.so", "fclose"), 
            "int", ["pointer"]);

        var filepathPtr = Memory.allocUtf8String(filepath);
        var modePtr = Memory.allocUtf8String(mode || "w");
        var file = fopen(filepathPtr, modePtr);
        
        if (file.isNull()) {
            console.error("[-] 无法打开文件:", filepath);
            return false;
        }

        var buffer, size;
        if (typeof content === "string") {
            // 字符串模式
            buffer = Memory.allocUtf8String(content);
            size = content.length;
        } else if (content instanceof ArrayBuffer) {
            // 二进制模式
            buffer = Memory.alloc(content.byteLength);
            Memory.writeByteArray(buffer, content);
            size = content.byteLength;
        } else {
            console.error("[-] 不支持的内容类型");
            fclose(file);
            return false;
        }

        var written = fwrite(buffer, 1, size, file);
        fclose(file);

        if (written === size) {
            console.log("[+] 文件写入成功:", filepath, "字节数:", written);
            return true;
        } else {
            console.error("[-] 写入不完整:", written, "/", size);
            return false;
        }
    } catch (e) {
        console.error("[-] 文件写入失败:", e);
        return false;
    }
}

// ============ 使用示例 ============

// 示例1: 使用 Frida API 写字符串
function example1() {
    writeFileByFrida("/sdcard/test_string.txt", "Hello Frida!", "w");
}

// 示例2: 使用 Frida API 写二进制
function example2() {
    var binaryData = new Uint8Array([0x48, 0x65, 0x6C, 0x6C, 0x6F]).buffer;
    writeFileByFrida("/sdcard/test_binary.bin", binaryData, "wb");
}

// 示例3: 使用 libc 写字符串
function example3() {
    writeFileByLibc("/sdcard/test_libc.txt", "Hello from libc!", "w");
}

// 示例4: 使用 libc 写二进制
function example4() {
    var binaryData = new Uint8Array([0xDE, 0xAD, 0xBE, 0xEF]).buffer;
    writeFileByLibc("/sdcard/test_libc.bin", binaryData, "wb");
}

// 示例5: 追加模式
function example5() {
    writeFileByFrida("/sdcard/test_append.txt", "第一行\n", "w");
    writeFileByFrida("/sdcard/test_append.txt", "第二行\n", "a");
}