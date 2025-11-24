// Monitor ArrayList operations
// 监控 ArrayList 操作
// java.util.ArrayList: 动态数组，Java中最常用的集合类之一。
// 用途：存储列表数据，如参数列表、商品列表、用户列表等。
// 逆向价值：**高**。应用常使用ArrayList存储一组关键参数（如键值对列表），Hook add/set/get 可以监控到数据的收集、修改和读取过程。
function hook_monitor_ArrayList() {
    Java.perform(function () {
        let java_util_ArrayList = Java.use("java.util.ArrayList");
        
        // 要监控的关键词
        let targetKeywords = [
            // 请求头相关
            "sign", "token", "auth", "authorization", "cookie", "session", 
            "x-sign", "x-token", "user-agent", "content-type", "accept",
            "referer", "host", "connection", "accept-encoding",
            
            // 参数相关
            "param", "data", "body", "query", "form", "json", "xml",
            "id", "uid", "userid", "username", "password", "phone", "email",
            "timestamp", "nonce", "version", "appkey", "secret",
            
            // 响应相关
            "code", "status", "message", "result", "data", "error", "success"
        ];
        
        // 辅助函数：打印调用栈
        function showJavaStacks() {
            console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        }

        // 辅助函数：检查是否包含目标关键词
        function containsTargetKeywords(obj) {
            if (!obj) return false;
            let str = obj.toString().toLowerCase();
            for (let i = 0; i < targetKeywords.length; i++) {
                if (str.includes(targetKeywords[i])) {
                    return true;
                }
            }
            return false;
        }
        
        // 辅助函数：打印 ArrayList 内容
        function printArrayListContent(list, methodName) {
            try {
                let size = list.size();
                console.log(`ArrayList content after ${methodName} (size=${size}):`);
                for (let i = 0; i < size; i++) {
                    let item = list.get(i);
                    console.log(`  [${i}] = ${item}`);
                }
            } catch (e) {
                console.log(`Cannot print ArrayList content: ${e}`);
            }
        }
        
        // 1. add(E e)
        // 作用: 向列表末尾添加元素。
        // 逆向场景：监控应用正在收集哪些数据（如收集参数准备签名）。
        java_util_ArrayList["add"].overload('java.lang.Object').implementation = function(item) {
            let result = this["add"](item);
            if (containsTargetKeywords(item)) {
                console.log(`[->] java_util_ArrayList.add(Object) is called!`);
                console.log(`    ->item= ${item}`);
                showJavaStacks();
            }
            return result;
        };
        
        // 2. add(int index, E element)
        // 作用: 在指定位置插入元素。
        // 逆向场景：同 add，但指定了位置。
        java_util_ArrayList["add"].overload('int', 'java.lang.Object').implementation = function(index, item) {
            let result = this["add"](index, item);
            if (containsTargetKeywords(item)) {
                console.log(`[->] java_util_ArrayList.add(int, Object) is called!`);
                console.log(`    ->index= ${index}`);
                console.log(`    ->item= ${item}`);
                showJavaStacks();
            }
            return result;
        };
        
        // 3. addAll(Collection<? extends E> c)
        // 作用: 添加一个集合的所有元素。
        // 逆向场景：批量数据处理。
        java_util_ArrayList["addAll"].overload('java.util.Collection').implementation = function(collection) {
            let result = this["addAll"](collection);
            console.log(`[->] java_util_ArrayList.addAll is called!`);
            console.log("    ->Added collection content:");
            try {
                let iterator = collection.iterator();
                while (iterator.hasNext()) {
                    let item = iterator.next();
                    console.log(`      ${item}`);
                }
            } catch (e) {
                console.log(`Cannot iterate collection: ${e}`);
            }
            showJavaStacks();
            return result;
        };
        
        // 4. set(int index, E element)
        // 作用: 修改指定位置的元素。
        // 逆向场景：监控数据的篡改或修正。
        java_util_ArrayList["set"].implementation = function(index, element) {
            let result = this["set"](index, element);
            if (containsTargetKeywords(element)) {
                console.log(`[->] java_util_ArrayList.set is called!`);
                console.log(`    ->index= ${index}`);
                console.log(`    ->newElement= ${element}`);
                console.log(`    ->oldElement= ${result}`);
                showJavaStacks();
            }
            return result;
        };
        
        // 5. get(int index)
        // 作用: 获取指定位置的元素。
        // 逆向场景：监控应用读取了哪些数据（如取出某个参数进行加密）。
        java_util_ArrayList["get"].implementation = function(index) {
            let result = this["get"](index);
            if (containsTargetKeywords(result)) {
                console.log(`[->] java_util_ArrayList.get is called!`);
                console.log(`    ->index= ${index}`);
                console.log(`    ->result= ${result}`);
                showJavaStacks();
            }
            return result;
        };
        
        // 6. remove(int index)
        // 作用: 删除指定位置的元素。
        // 逆向场景：数据清洗。
        java_util_ArrayList["remove"].overload('int').implementation = function(index) {
            let result = this["remove"](index);
            if (containsTargetKeywords(result)) {
                console.log(`[->] java_util_ArrayList.remove(int) is called!`);
                console.log(`    ->index= ${index}`);
                console.log(`    ->removedElement= ${result}`);
                showJavaStacks();
            }
            return result;
        };
        
        // 7. clear()
        // 作用: 清空列表。
        // 逆向场景：重置状态。
        java_util_ArrayList["clear"].implementation = function() {
            console.log(`[->] java_util_ArrayList.clear is called!`);
            printArrayListContent(this, "clear");
            showJavaStacks();
            return this["clear"]();
        };
        
        // 8. 构造函数
        // 作用: 创建 ArrayList 实例。
        java_util_ArrayList["$init"].overload().implementation = function() {
            console.log(`[->] java_util_ArrayList.$init() is called!`);
            // showJavaStacks(); // Too noisy usually
            return this["$init"]();
        };
        
        java_util_ArrayList["$init"].overload('int').implementation = function(initialCapacity) {
            console.log(`[->] java_util_ArrayList.$init(int) is called!`);
            console.log(`    ->initialCapacity= ${initialCapacity}`);
            return this["$init"](initialCapacity);
        };
    });
    console.warn(`[*] hook_monitor_ArrayList is injected!`);
}

// Execute the hook
hook_monitor_ArrayList();

/*
关于 ArrayList 的详解

java.util.ArrayList 是 Java 中最常用的动态数组实现。

核心机制：
- 内部维护一个 Object[] elementData 数组。
- 容量不足时自动扩容（通常是 1.5 倍）。
- 非线程安全（多线程环境下推荐 Collections.synchronizedList 或 CopyOnWriteArrayList）。

逆向价值：
1. 参数收集：很多 App 在计算签名之前，会把所有参数放到一个 ArrayList 里进行排序或拼接。
2. 响应解析：服务器返回的列表数据（如商品列表、评论列表）通常会被解析成 ArrayList。
3. Hook `add` 和 `get` 可以监控到数据的流入和流出。

速记：
1. 看到 `new ArrayList()`，通常是在准备容器。
2. 看到 `addAll()`，是在合并数据。
3. 看到 `toArray()`，是在转数组，可能是为了传给底层 C++ 代码或进行签名计算。
*/
