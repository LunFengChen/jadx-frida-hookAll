// 功能：打印 Java 的各种 Map 对象

// 方法1(推荐): 遍历 Map 并打印内容
function showJavaMap(map, mapName) {
    if (map == null) { return; }
    console.log((mapName || "Map") + " content:");
    var keys = map.keySet().toArray();
    for (var i = 0; i < keys.length; i++) {
        var key = keys[i];
        var value = map.get(key);
        var value_str = "";

        // 处理 byte[] 类型的值
        if (value != null && value.getClass().getName() === "[B") {
            var JDKClass_String = Java.use('java.lang.String');
            value_str = JDKClass_String.$new(Java.array('byte', value)).toString();
        } else {
            value_str = value;
        }
        console.log("  " + key + " = " + value_str);
    }
}

// 方法2: 使用迭代器遍历 Map
// 这个利用的是Java的Map的api
function iterateMap(map) {
    if (map == null) { return; }
    var keyset = map.keySet();
    var it = keyset.iterator();
    console.log("Map contents:");
    while (it.hasNext()) {
        var key = it.next();
        var value = map.get(key);
        var keystr = key ? key.toString() : "null";
        var valuestr = value ? value.toString() : "null";
        console.log("  " + keystr + " = " + valuestr);
    }
}

// 方法3: 使用 Gson 打印 Map (需要先加载 r0gson.dex)
// 下载见r0ysue博客: http://github.com/r0ysue/AndroidSecurityStudy/blob/master/FRIDA/r0gson.dex.zip
// 使用前需要执行: adb push r0gson.dex /data/local/tmp/r0gson.dex
// 用这个的好处是 如果app也用了，避免类名冲突
function mapToJson(map) {
    Java.openClassFile("/data/local/tmp/r0gson.dex").load();
    var GsonClass_Gson = Java.use('com.r0ysue.gson.Gson');
    return GsonClass_Gson.$new().toJsonTree(map).getAsJsonObject();
}

// 注意事项：
// 1. showJavaMap 是最常用的方法，推荐使用
// 2. 如果 Map 的值是 byte[]，会自动转换为字符串显示
// 3. mapToJson 需要先 push r0gson.dex 到设备: adb push r0gson.dex /data/local/tmp/

/*
关于 打印 Map (Print Map) 的详解

Map 是 Java 中最常用的键值对容器 (如 HashMap, TreeMap, LinkedHashMap)。
在逆向分析中，Map 经常用来存储请求参数、配置信息、Header 等。

核心功能：
1. 遍历打印：
   - 直接打印 Map 对象通常只能看到 [Object object] 或者 "java.util.HashMap@xxxx"。
   - 提供了 `showJavaMap` 函数，可以遍历 Map 的所有 Key 和 Value 并打印出来。

2. 自动处理 byte[](后续支持更多)：
   - 如果 Value 是 byte[] (字节数组)，脚本会自动将其转换为字符串显示，方便查看。

3. Gson 支持 (可选)：
   - 如果想看更漂亮的 JSON 格式，可以使用 `mapToJson` (需要 r0gson.dex)。

速记：
1. 看到参数类型是 `java.util.Map`，直接把这个脚本粘过去，用 `showJavaMap(map)` 打印。 如果是我改的jadx，按F会自动生成该辅助函数
2. 这是分析签名算法（通常涉及参数排序和拼接）的神器。
*/
