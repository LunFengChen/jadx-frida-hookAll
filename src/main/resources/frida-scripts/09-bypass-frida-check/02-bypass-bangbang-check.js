function hook_monitor_clone() {
    var clone = Module.findExportByName('libc.so', 'clone');
    Interceptor.attach(clone, {
        onEnter: function(args) {
            if (args[3] == 0) return;
            
            try {
                var fn = args[3].add(96).readPointer();
                var module = Process.findModuleByAddress(fn);
                
                if (module) {
                    var offset = fn.sub(module.base).toString(16);
                    
                    if (killSo && module.name.includes("libDexHelper.so")) {
                        console.warn(`[Kill] ${module.name} + 0x${offset}`);
                        hook_replace_void(fn);
                    } else {
                        console.log(`[Clone] ${module.name} + 0x${offset}`);
                    }
                }
            } catch(e) {}
        }
    });
}

function hook_replace_void(fn_address) {
    // 用replace函数直接对目标函数置空
    Interceptor.replace(fn_address, new NativeCallback(function () {
        console.warn(`[!] replace_void ${fn_address}!`)
    }, 'void', []));
}


// 用法
hook_monitor_clone(); 
// 注意：这脚本只能杀旧版梆梆，新版用不了，别跑来问为什么不行
// 较为新版的梆梆需要先过一个检测，再hook clone杀线程， 参考：东方玻璃的文章 https://bbs.kanxue.com/thread-289545.htm
// 最新的梆梆还在学习中