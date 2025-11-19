// Load external DEX files
// 加载外部DEX文件

// ========== 加载 Gson DEX ==========
// 推荐使用 r0ysue 重新编译的 gson
// 下载: https://github.com/r0ysue/r0gson
// 使用步骤：
// 1. 下载 r0gson.dex
// 2. adb push r0gson.dex /data/local/tmp/r0gson.dex
// 3. 在 Frida 脚本中加载

Java.perform(function() {
    // 加载 gson
    Java.openClassFile("/data/local/tmp/r0gson.dex").load(); 
    
    console.log("[+] r0gson.dex loaded successfully");
    
    // 使用 Gson 打印 Map
    function maptoJGon(map){
        var Gson = Java.use('com.r0ysue.gson.Gson').$new();
        return Gson.toJsonTree(map).getAsJsonObject();
    }
    
    // 测试示例
    // var testMap = Java.use("java.util.HashMap").$new();
    // testMap.put("key1", "value1");
    // testMap.put("key2", "value2");
    // console.log(maptoJGon(testMap));
});

// ========== 加载自定义DEX ==========
/*
通用步骤：
1. 编译你的DEX文件
2. 将DEX文件推送到手机：
   adb push your_dex.dex /data/local/tmp/your_dex.dex
3. 在Frida脚本中加载：
   Java.openClassFile("/data/local/tmp/your_dex.dex").load();
4. 使用DEX中的类：
   var YourClass = Java.use("com.example.YourClass");
   
注意事项：
- 确保DEX文件路径正确
- 确保应用有读取该路径的权限
- DEX文件中的类不能与应用中已有的类冲突
*/

// ========== 动态加载DEX示例 ==========
function loadCustomDex(dexPath) {
    Java.perform(function() {
        try {
            Java.openClassFile(dexPath).load();
            console.log(`[+] Successfully loaded DEX: ${dexPath}`);
        } catch (e) {
            console.error(`[-] Failed to load DEX: ${dexPath}`);
            console.error(e);
        }
    });
}

// 使用示例
// loadCustomDex("/data/local/tmp/custom.dex");
