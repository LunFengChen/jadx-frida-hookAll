// ClassLoader helper functions
// ClassLoader 问题处理

// ========== 寻找并设置正确的ClassLoader ==========
function findCorrectClassLoader(className) {
    console.log("[*] Attempting to find correct ClassLoader...");
    let foundLoaders = []; 
    
    Java.enumerateClassLoaders({
        onMatch: function(loader) {
            try {
                if (loader.findClass(className)) {
                    console.log("[+] Found correct ClassLoader");
                    foundLoaders.push(loader); 
                }
            } catch (e) {}
        },
        onComplete: function() {
            if (foundLoaders.length === 0) {
                console.warn("[*] Could not find correct ClassLoader, using default!");
            } else {
                console.log("[*] Found " + foundLoaders.length + " ClassLoader(s)");
            }
        }
    });
    
    // 返回找到的最后一个ClassLoader，如果没有找到则返回null
    return foundLoaders.length > 0 ? foundLoaders[foundLoaders.length - 1] : null;
}

function setClassloader(loader) {
    if (loader) {
        Java.classFactory.loader = loader;
        console.log("[+] ClassLoader set successfully");
    } else {
        console.warn("[-] Cannot set null ClassLoader");
    }
}

// ========== 使用示例 ==========
// var loader = findCorrectClassLoader("com.downjoy.db.DatabaseUtil");
// setClassloader(loader);

// ========== Hook绑定说明 ==========
/*
Java.use和implementation的区别：

1. 获取类引用阶段 (Java.use)
   Frida 会尝试找到能够加载目标类的 ClassLoader
   可能使用当前设置的 Java.classFactory.loader，或者自动查找一个可用的 ClassLoader
   但这只是获取一个类引用，并不决定后续 Hook 绑定的 ClassLoader
   所以如果使用这个进行主动调用是没问题的，但是hook监控就不行

2. Hook 设置阶段 (implementation)
   当您设置 implementation 时，Frida 会将 Hook 绑定到当前有效的 ClassLoader
   这个 ClassLoader 可能是：
   - 显式设置的 Java.classFactory.loader
   - Frida 的默认 ClassLoader
   - 最近一次成功执行 Java.use 时使用的 ClassLoader
   
所以有的时候主动调用可以，但是hook不到是因为implemention在进行hook绑定的时候
没有绑定到正确的classloader！
*/

// ========== 加壳和ClassLoader ==========
/*
加壳之后的hook需要使用classLoader，每一个加载的dex都对应有一个classLoader
然后它们之间互相之间的函数调用，也需要使用到对方的classLoader才可以
没有办法直接使用，我们hook也需要使用到这些，因为这样子才能hook到这个java函数的具体地址
然后变成一个native函数再来进行hook

示例：
*/
function hookWithEnumerateClassLoaders() {
    Java.enumerateClassLoadersSync().forEach(classLoader => {
        try {
            if (classLoader.loadClass("ot2.b")) {
                Java.classFactory.loader = classLoader;
                console.log(classLoader)
                let C82252b = Java.use("ot2.b");
                C82252b["getBdOz"].implementation = function (context) {
                    console.log(`C82252b.getBdOz is called: context=${context}`);
                    let result = this["getBdOz"](context);
                    console.log(`C82252b.getBdOz result=${result}`);
                    return result;
                };
            }
        } catch (e) {
            // console.log(e)
        }
    })
}

// 使用示例
// hookWithEnumerateClassLoaders();
