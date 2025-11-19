// Monitor ArrayList operations
// 监控 ArrayList 操作
function showJavaStacks() {
    console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
}

function hook_monitor_ArrayList() {
    Java.perform(function () {
        let ArrayList = Java.use("java.util.ArrayList");
        let java_lang_String = Java.use("java.lang.String");
        
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
                console.log(`ArrayList content after ${methodName} (size=${list.size()}):`);
                for (let i = 0; i < list.size(); i++) {
                    let item = list.get(i);
                    console.log(`  [${i}] = ${item}`);
                }
            } catch (e) {
                console.log(`Cannot print ArrayList content: ${e}`);
            }
        }
        
        // 1. add(E e)
        ArrayList.add.overload('java.lang.Object').implementation = function(item) {
            let result = this.add(item);
            if (containsTargetKeywords(item)) {
                console.log(`\n================= ArrayList.add =================`);
                console.log(`Item: ${item}`);
                showJavaStacks();
            }
            return result;
        };
        
        // 2. add(int index, E element)
        ArrayList.add.overload('int', 'java.lang.Object').implementation = function(index, item) {
            let result = this.add(index, item);
            if (containsTargetKeywords(item)) {
                console.log(`\n================= ArrayList.add(index, element) =================`);
                console.log(`Index: ${index}, Item: ${item}`);
                showJavaStacks();
            }
            return result;
        };
        
        // 3. addAll(Collection<? extends E> c)
        ArrayList.addAll.overload('java.util.Collection').implementation = function(collection) {
            let result = this.addAll(collection);
            console.log(`\n================= ArrayList.addAll =================`);
            console.log("Added collection:");
            try {
                let iterator = collection.iterator();
                while (iterator.hasNext()) {
                    let item = iterator.next();
                    console.log(`  ${item}`);
                }
            } catch (e) {
                console.log(`Cannot iterate collection: ${e}`);
            }
            showJavaStacks();
            return result;
        };
        
        // 4. set(int index, E element)
        ArrayList.set.implementation = function(index, element) {
            let result = this.set(index, element);
            if (containsTargetKeywords(element)) {
                console.log(`\n================= ArrayList.set =================`);
                console.log(`Index: ${index}, New element: ${element}, Old element: ${result}`);
                showJavaStacks();
            }
            return result;
        };
        
        // 5. get(int index)
        ArrayList.get.implementation = function(index) {
            let result = this.get(index);
            if (containsTargetKeywords(result)) {
                console.log(`\n================= ArrayList.get =================`);
                console.log(`Index: ${index}, Result: ${result}`);
                showJavaStacks();
            }
            return result;
        };
        
        // 6. remove(int index)
        ArrayList.remove.overload('int').implementation = function(index) {
            let result = this.remove(index);
            if (containsTargetKeywords(result)) {
                console.log(`\n================= ArrayList.remove(index) =================`);
                console.log(`Index: ${index}, Removed element: ${result}`);
                showJavaStacks();
            }
            return result;
        };
        
        // 7. clear()
        ArrayList.clear.implementation = function() {
            console.log(`\n================= ArrayList.clear =================`);
            printArrayListContent(this, "clear");
            showJavaStacks();
            return this.clear();
        };
        
        // 8. 构造函数
        ArrayList.$init.overload().implementation = function() {
            console.log(`\n================= ArrayList.<init>() =================`);
            showJavaStacks();
            return this.$init();
        };
        
        ArrayList.$init.overload('int').implementation = function(initialCapacity) {
            console.log(`\n================= ArrayList.<init>(int) =================`);
            console.log(`Initial capacity: ${initialCapacity}`);
            showJavaStacks();
            return this.$init(initialCapacity);
        };
        
    });
    console.warn(`[*] hook_monitor_ArrayList is injected`)
}

// Execute the hook
hook_monitor_ArrayList();
