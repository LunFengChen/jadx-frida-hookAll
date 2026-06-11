if (Java.available) {
    Java.perform(function () {
        let WXSDKInstance = Java.use("com.taobao.weex.WXSDKInstance");
        WXSDKInstance["render"].overload('java.lang.String', 'java.lang.String', 'java.util.Map', 'java.lang.String', 'com.taobao.weex.common.WXRenderStrategy').implementation = function (str, str2, map, str3, wXRenderStrategy) {
            // console.log(`WXSDKInstance.render is called: str=${str}, str2=${str2}, map=${map}, str3=${str3}, wXRenderStrategy=${wXRenderStrategy}`);
            this["render"](str, str2, map, str3, wXRenderStrategy);
            write_file_1(str3, str2)
        };
    });
}

function sanitizeFileName(fileName) {
    // 移除路径分隔符等非法字符
    return fileName.replace(/[\/\\:*?"<>|{}]/g, "_");
}

function trimUnderscores(str) {
    // 先去除空白字符，再去去除下划线
    return str.trim().replace(/^_+|_+$/g, '');
}


function write_file_1(filename, data) {
    //frida 的api来写文件
    filename = sanitizeFileName(filename)
    filename = trimUnderscores(filename)

    console.log(filename)

    // 先检查文件是否存在，如果存在则删除
    try {
        var existingFile = new File("/sdcard/Download/demo-js/" + filename, "r");
        if (existingFile) {
            existingFile.close();
            // 删除已存在的文件
            File.remove("/sdcard/Download/demo-js/" + filename);
        }
    } catch (e) {

    }

    var file = new File("/sdcard/Download/demo-js/" + filename, "w");
    file.write(data);
    file.flush();
    file.close();
}