// 功能：打印 Java Map 对象

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
// 使用前需要执行: adb push r0gson.dex /data/local/tmp/r0gson.dex
function mapToJson(map) {
    Java.openClassFile("/data/local/tmp/r0gson.dex").load();
    var GsonClass_Gson = Java.use('com.r0ysue.gson.Gson');
    return GsonClass_Gson.$new().toJsonTree(map).getAsJsonObject();
}

// 注意事项：
// 1. showJavaMap 是最常用的方法，推荐使用
// 2. 如果 Map 的值是 byte[]，会自动转换为字符串显示
// 3. mapToJson 需要先 push r0gson.dex 到设备: adb push r0gson.dex /data/local/tmp/

// 使用示例:
// function hook_monitor_calcSignature(){
//     Java.perform(function () {
//         let com_iget_baselib_BaseApi = Java.use("com.iget.baselib.BaseApi");
//         com_iget_baselib_BaseApi["calcSignature"].implementation = function (map, map2) {
//             console.log(`[->] com_iget_baselib_BaseApi.calcSignature is called! args are as follows:`);
//             showJavaMap(map, "map");
//             showJavaMap(map2, "map2");
//             var retval = this["calcSignature"](map, map2);
//             console.log(`[<-] com_iget_baselib_BaseApi.calcSignature ended! \n    retval= ${retval}`);
//             return retval;
//         };
//     });
//     console.warn(`[*] hook_monitor_calcSignature is injected!`);
// };
// hook_monitor_calcSignature();
