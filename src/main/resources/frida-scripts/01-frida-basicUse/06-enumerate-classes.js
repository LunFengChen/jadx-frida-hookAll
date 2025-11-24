// 枚举所有已加载的类与类的方法
function hook_enumerateClasses(){
    Java.perform(function(){
        // 枚举所有的类与类的所有方法,异步枚举
        Java.enumerateLoadedClasses({
            onMatch: function(name, handle){
                // 过滤类名
                if(name.indexOf("com.xiaofeng.Demo") != -1){
                    console.log("Found class:", name);
                    let loadedClass = Java.use(name);
                    console.log("Class object:", loadedClass);
                    let methods = loadedClass.class.getDeclaredMethods();
                    console.log("Methods:", methods);
                }
            },
            onComplete: function(){
                console.log("Enumeration completed");
            }
        })
    })
    console.warn(`[*] hook_enumerateClasses is injected!`);
};
hook_enumerateClasses();
