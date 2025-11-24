// Monitor all Map operations
// 监控 Map 接口及其常见实现的所有方法
// java.util.Map: 键值对集合接口。
// 用途：存储键值对数据。
// 逆向价值：**极高**。Map是Java中最常用的数据结构之一。
//           应用内部几乎所有的配置、参数、请求体、响应解析结果，最终都会以Map的形式存在。
//           Hook Map操作（尤其是put和get）是获取关键数据（如Token, Key, Sign）的万能钥匙。
function hook_monitor_all_Map() {
    Java.perform(function () {
        let Map = Java.use("java.util.Map");
        let HashMap = Java.use("java.util.HashMap");
        let LinkedHashMap = Java.use("java.util.LinkedHashMap");
        let TreeMap = Java.use("java.util.TreeMap");
        let Hashtable = Java.use("java.util.Hashtable");
        let ConcurrentHashMap = Java.use("java.util.concurrent.ConcurrentHashMap");
        
        // 要监控的关键键名
        let targetKeys = ["sign", "token", "auth", "authorization", "cookie", "session", "x-sign", "x-token", "key", "secret"];
        
        // 辅助函数：打印调用栈
        function showJavaStacks() {
            console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        }

        // 辅助函数：检查键是否为目标键
        function isTargetKey(key) {
            if (key == null) return false;
            let keyStr = key.toString().toLowerCase();
            for (let i = 0; i < targetKeys.length; i++) {
                if (keyStr.includes(targetKeys[i])) {
                    return true;
                }
            }
            return false;
        }
        
        // 辅助函数：打印 Map 内容
        function printMapContent(map, methodName) {
            try {
                let entrySet = map.entrySet();
                let iterator = entrySet.iterator();
                console.log(`Map content after ${methodName}:`);
                while (iterator.hasNext()) {
                    let entry = iterator.next();
                    let key = entry.getKey();
                    let value = entry.getValue();
                    console.log(`  ${key} = ${value}`);
                }
            } catch (e) {
                console.log(`Cannot print map content: ${e}`);
            }
        }
        
        // 1. put(K key, V value)
        // 作用: 添加键值对。
        // 逆向场景：监控参数收集过程。
        Map["put"].implementation = function(key, value) {
            let result = this["put"](key, value);
            if (isTargetKey(key)) {
                console.log(`[->] Map.put is called!`);
                console.log(`    ->key= ${key}`);
                console.log(`    ->value= ${value}`);
                showJavaStacks();
            }
            return result;
        };
        
        // 2. putAll(Map<? extends K, ? extends V> m)
        // 作用: 批量添加。
        // 逆向场景：监控批量参数合并。
        Map["putAll"].implementation = function(map) {
            let result = this["putAll"](map);
            console.log(`[->] Map.putAll is called!`);
            console.log("    ->Source map:");
            printMapContent(map, "putAll");
            showJavaStacks();
            return result;
        };
        
        // 3. get(Object key)
        // 作用: 读取值。
        // 逆向场景：监控应用读取了哪些关键配置。
        Map["get"].implementation = function(key) {
            let result = this["get"](key);
            if (isTargetKey(key)) {
                console.log(`[->] Map.get is called!`);
                console.log(`    ->key= ${key}`);
                console.log(`    ->result= ${result}`);
                showJavaStacks();
            }
            return result;
        };
        
        // 4. remove(Object key)
        Map["remove"].implementation = function(key) {
            let result = this["remove"](key);
            if (isTargetKey(key)) {
                console.log(`[->] Map.remove is called!`);
                console.log(`    ->key= ${key}`);
                console.log(`    ->removed value= ${result}`);
                showJavaStacks();
            }
            return result;
        };
        
        // 5. containsKey(Object key)
        Map["containsKey"].implementation = function(key) {
            let result = this["containsKey"](key);
            if (isTargetKey(key)) {
                console.log(`[->] Map.containsKey is called!`);
                console.log(`    ->key= ${key}`);
                console.log(`    ->contains= ${result}`);
                showJavaStacks();
            }
            return result;
        };
        
        // 6. containsValue(Object value)
        Map["containsValue"].implementation = function(value) {
            let result = this["containsValue"](value);
            // 检查值是否包含敏感信息
            if (value != null && value.toString().length > 10) {
                console.log(`[->] Map.containsValue is called!`);
                console.log(`    ->value= ${value}`);
                console.log(`    ->contains= ${result}`);
                showJavaStacks();
            }
            return result;
        };
        
        // 7. clear()
        Map["clear"].implementation = function() {
            console.log(`[->] Map.clear is called!`);
            console.log("    ->Map is being cleared");
            printMapContent(this, "clear");
            showJavaStacks();
            return this["clear"]();
        };
        
        // 8. HashMap 构造函数
        HashMap["$init"].overload().implementation = function() {
            console.log(`[->] HashMap.$init() is called!`);
            // showJavaStacks();
            return this["$init"]();
        };
        
        HashMap["$init"].overload('int').implementation = function(initialCapacity) {
            console.log(`[->] HashMap.$init(int) is called!`);
            console.log(`    ->initialCapacity= ${initialCapacity}`);
            // showJavaStacks();
            return this["$init"](initialCapacity);
        };
        
        HashMap["$init"].overload('int', 'float').implementation = function(initialCapacity, loadFactor) {
            console.log(`[->] HashMap.$init(int, float) is called!`);
            console.log(`    ->initialCapacity= ${initialCapacity}`);
            console.log(`    ->loadFactor= ${loadFactor}`);
            // showJavaStacks();
            return this["$init"](initialCapacity, loadFactor);
        };
        
        HashMap["$init"].overload('java.util.Map').implementation = function(map) {
            console.log(`[->] HashMap.$init(Map) is called!`);
            console.log("    ->Source map:");
            printMapContent(map, "HashMap constructor");
            showJavaStacks();
            return this["$init"](map);
        };
        
        // 9. 其他 Map 实现的构造函数
        // 通常不需要全部监控，因为它们最终会调用 Map 接口的方法，或者我们已经 Hook 了 Map 接口
        // 如果需要针对特定实现类监控，可以取消注释
        /*
        LinkedHashMap["$init"].overload().implementation = function() { ... };
        TreeMap["$init"].overload().implementation = function() { ... };
        */
    });
    console.warn(`[*] hook_monitor_all_Map is injected!`);
};

hook_monitor_all_Map();
