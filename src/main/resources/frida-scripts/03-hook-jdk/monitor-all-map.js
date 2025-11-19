// Monitor all Map operations
// 监控 Map 接口及其常见实现的所有方法
function showJavaStacks() {
    console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
}

function hook_monitor_all_Map() {
    Java.perform(function () {
        let Map = Java.use("java.util.Map");
        let HashMap = Java.use("java.util.HashMap");
        let LinkedHashMap = Java.use("java.util.LinkedHashMap");
        let TreeMap = Java.use("java.util.TreeMap");
        let Hashtable = Java.use("java.util.Hashtable");
        let ConcurrentHashMap = Java.use("java.util.concurrent.ConcurrentHashMap");
        
        // 要监控的关键键名
        let targetKeys = ["sign", "token", "auth", "authorization", "cookie", "session", "x-sign", "x-token"];
        
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
        Map.put.implementation = function(key, value) {
            let result = this.put(key, value);
            if (isTargetKey(key)) {
                console.log(`\n================= Map.put =================`);
                console.log(`Key: ${key}, Value: ${value}`);
                showJavaStacks();
            }
            return result;
        };
        
        // 2. putAll(Map<? extends K, ? extends V> m)
        Map.putAll.implementation = function(map) {
            let result = this.putAll(map);
            console.log(`\n================= Map.putAll =================`);
            console.log("Source map:");
            printMapContent(map, "putAll");
            showJavaStacks();
            return result;
        };
        
        // 3. get(Object key)
        Map.get.implementation = function(key) {
            let result = this.get(key);
            if (isTargetKey(key)) {
                console.log(`\n================= Map.get =================`);
                console.log(`Key: ${key}, Result: ${result}`);
                showJavaStacks();
            }
            return result;
        };
        
        // 4. remove(Object key)
        Map.remove.implementation = function(key) {
            let result = this.remove(key);
            if (isTargetKey(key)) {
                console.log(`\n================= Map.remove =================`);
                console.log(`Key: ${key}, Removed value: ${result}`);
                showJavaStacks();
            }
            return result;
        };
        
        // 5. containsKey(Object key)
        Map.containsKey.implementation = function(key) {
            let result = this.containsKey(key);
            if (isTargetKey(key)) {
                console.log(`\n================= Map.containsKey =================`);
                console.log(`Key: ${key}, Contains: ${result}`);
                showJavaStacks();
            }
            return result;
        };
        
        // 6. containsValue(Object value)
        Map.containsValue.implementation = function(value) {
            let result = this.containsValue(value);
            // 检查值是否包含敏感信息
            if (value != null && value.toString().length > 10) {
                console.log(`\n================= Map.containsValue =================`);
                console.log(`Value: ${value}, Contains: ${result}`);
                showJavaStacks();
            }
            return result;
        };
        
        // 7. clear()
        Map.clear.implementation = function() {
            console.log(`\n================= Map.clear =================`);
            console.log("Map is being cleared");
            printMapContent(this, "clear");
            showJavaStacks();
            return this.clear();
        };
        
        // 8. HashMap 构造函数
        HashMap.$init.overload().implementation = function() {
            console.log(`\n================= HashMap.<init>() =================`);
            showJavaStacks();
            return this.$init();
        };
        
        HashMap.$init.overload('int').implementation = function(initialCapacity) {
            console.log(`\n================= HashMap.<init>(int) =================`);
            console.log(`Initial capacity: ${initialCapacity}`);
            showJavaStacks();
            return this.$init(initialCapacity);
        };
        
        HashMap.$init.overload('int', 'float').implementation = function(initialCapacity, loadFactor) {
            console.log(`\n================= HashMap.<init>(int, float) =================`);
            console.log(`Initial capacity: ${initialCapacity}, Load factor: ${loadFactor}`);
            showJavaStacks();
            return this.$init(initialCapacity, loadFactor);
        };
        
        HashMap.$init.overload('java.util.Map').implementation = function(map) {
            console.log(`\n================= HashMap.<init>(Map) =================`);
            console.log("Source map:");
            printMapContent(map, "HashMap constructor");
            showJavaStacks();
            return this.$init(map);
        };
        
        // 9. 其他 Map 实现的构造函数
        LinkedHashMap.$init.overload().implementation = function() {
            console.log(`\n================= LinkedHashMap.<init>() =================`);
            showJavaStacks();
            return this.$init();
        };
        
        TreeMap.$init.overload().implementation = function() {
            console.log(`\n================= TreeMap.<init>() =================`);
            showJavaStacks();
            return this.$init();
        };
        
        Hashtable.$init.overload().implementation = function() {
            console.log(`\n================= Hashtable.<init>() =================`);
            showJavaStacks();
            return this.$init();
        };
        
        ConcurrentHashMap.$init.overload().implementation = function() {
            console.log(`\n================= ConcurrentHashMap.<init>() =================`);
            showJavaStacks();
            return this.$init();
        };
    });
    console.warn(`[*] hook_monitor_all_Map is injected`)
}

// Execute the hook
hook_monitor_all_Map();
