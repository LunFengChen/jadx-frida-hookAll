/**
 * 绕过移动安全联盟frida检测的脚本
 * 对应的so是libmsaoaidsec.so
 */

function hook_dlopen() {
    Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"), {
        onEnter: function (args) {
            this.fileName = args[0].readCString();
            console.log(`[+] dlopen onEnter ==> ${this.fileName}`);
            // msa: 干掉入口函数
            if (this.fileName && this.fileName.includes("libmsaoaidsec.so")) {
                console.warn(`[+] dlopen onEnter ==> ${this.fileName}`);
                // 测试环境: win11, rusda16.2.1(抹除一些基础特征) + 本脚本即可绕过； 如果是比较强的魔改server, 不需要本脚本；

                // 通用1: 杀入口函数(msa是一个比较固定的sdk, 版本更迭慢, 最近的版本入口函数固定不变)
                hook_call_constructors_bypass_msa();

                // 通用2: 空替换(小部分情况不稳定)
                // replace_loadso(args[0], "");

                // 通用3: 重定向libc, 这里是后者(小部分情况不稳定)
                // replace_loadso(args[0], "libc.so");


                // 不通用思路4: 杀线程(检测到异常线程创建给他干掉)

                // 不通用思路5: 杀检测函数(pthread_create, clone入参就能拿到)

                // 不稳定思路6: 直接删除so, 有的时候会闪退
            }
        }, onLeave: function (retval) {
            // 要退出了
            try{
                let address_JNI_OnLoad = Module.getExportByName(this.fileName, 'JNI_OnLoad');
                if (address_JNI_OnLoad){
                    console.log(`[-] dlopen onLeave <== ${this.fileName}! found JNI_OnLoad, address: ${address_JNI_OnLoad}!`);
                }
                else {
                    console.log(`[-] dlopen onLeave <== ${this.fileName}`);
                }
            } catch (e){
                // 报错就不打印了
                // console.error(e)
            }
        }
    });
}


// 负责过msa的检测
function hook_call_constructors_bypass_msa() {
    // 1. 找linker
    var address_linker = module_linker = null;
    var module_linker = Process.findModuleByName(Process.pointerSize * 8 === 64 ? "linker64" : "linker"); // 拿到的是module
    if (!module_linker) {
        console.error("[*] error: can't find linker!")
    } else {
        address_linker = module_linker.base;
        console.warn(`[*] linker address: ${address_linker}, path: ${module_linker.path}!`);
    }

    // 2. 寻找call_constructors地址
    let address_call_constructors = null;
    let symbols = module_linker.enumerateSymbols();
    for (let index = 0; index < symbols.length; index++) {
        let symbol = symbols[index];
        // 查找名为"__dl__ZN6soinfo17call_constructorsEv"的符号地址
        if (symbol.name === "__dl__ZN6soinfo17call_constructorsEv") {
            address_call_constructors = symbol.address;
        }
    }
    if (!address_call_constructors) {
        console.warn("[*] not found call_constructors!")
    } else {
        console.warn(`[*] call_constructors address: ${address_call_constructors}, offest: ${address_call_constructors.sub(address_linker)}!`)
    }

    let listener = Interceptor.attach(address_call_constructors, {
        onEnter: function (args) {
            console.warn('[->] hook_linker_call_constructors onEnter');
            let secmodule = Process.findModuleByName("libmsaoaidsec.so");
            if (secmodule != null) {
                // arm64下 1BEC4也可以
                hook_replace_void(secmodule.base.add(Process.pointerSize * 8 === 64 ? 0x1B924 : 0x11E1C));
                console.warn("[*] bypassing check!")
                listener.detach();
            } else{
                console.warn("[!] not found msa!");
            }
        }, onLeave: function (retval) {
            console.warn("[<-] call_constructors onLeave");
        }
    })
}


// 负责替换要加载的so, 而不是直接删除
function replace_loadso(address_arg0, replace_libname){
    // 如果没报错 a)正常使用 b)不正常, 说明这个so不是关键的那一个  如果报错, 就是关键的so
    console.warn(`[!] replace so! ${address_arg0.readCString()} -> ${replace_libname}`);
    var address_arg0 = Memory.allocUtf8String(replace_libname);
};


function hook_replace_void(addr) {
    // nop函数
    console.warn(`[!] replace_void ${addr}!`)
    Interceptor.replace(addr, new NativeCallback(function () {
        // console.warn(`[!] replace_void ${addr}!`)
    }, 'void', []));
}


function nop_func(parg2){
    // 这样修改没有进行hook，不易被检测
    // 修改内存保护，使其可写
    Memory.protect(parg2, 4, 'rwx');
    // 使用 Arm64Writer 写入 'ret' 指令
    var writer = new Arm64Writer(parg2);
    writer.putRet();
    writer.flush();
    writer.dispose();
    console.warn(`[!] nop ${parg2} success!`);
}



// 这段代码是残次品，用于绕其他检测的，放这里吧
function hook_fake_pthread_create_bypass() {
    // 保存原始的pthread_create函数
    const pthread_create_addr = Module.findExportByName(null, "pthread_create");
    const pthread_create = new NativeFunction(pthread_create_addr, "int", ["pointer", "pointer", "pointer", "pointer"]);
    
    return new NativeCallback((parg0, parg1, parg2, parg3) => {
        const module = Process.findModuleByAddress(parg2);
        if (!module) {
            return pthread_create(parg0, parg1, parg2, parg3);
        }
        
        const so_name = module.name;
        const func_offset = parg2.sub(module.base).toString(16); // 转换为16进制字符串
        
        console.log(`[*] Thread creation attempt from ${so_name} at offset: 0x${func_offset}, arg's address: ${parg3.toString(16)}`);
        
        // 检查是否需要全杀这个SO的线程
        if (threadKillRules.killAll.includes(so_name)) {
            console.warn(`[!] Killing ALL threads from ${so_name} (global kill rule)`);
            return 0; // 返回0表示成功创建线程，但啥也没干
        }
        
        // 检查是否需要杀死特定偏移的线程
        if (threadKillRules.specific[so_name]) {
            // 检查是否在要杀死的特定偏移列表中
            if (threadKillRules.specific[so_name].includes(func_offset)) {
                console.warn(`[!] Killing specific thread from ${so_name} at offset: 0x${func_offset}`);
                return 0; // 返回0表示成功创建线程，但啥也没干
            }
        }
        
        // 正常的线程创建, 成功是返回0
        return pthread_create(parg0, parg1, parg2, parg3);
    }, "int", ["pointer", "pointer", "pointer", "pointer"]);
}


// 线程创建
function hook_replace_thread_create(){
    var new_pthread_create = hook_fake_pthread_create_bypass()
    var pthread_create_addr = Module.findExportByName(null, "pthread_create")
    // 函数替换
    Interceptor.replace(pthread_create_addr, new_pthread_create);
}


// 重定向部分特征检测: 此方法不一定有用, 一般是某些手机有问题然后辅助的时候用
function hook_monitor_maps_redirect() {
    Interceptor.attach(Module.findExportByName('libc.so', 'fopen'), {
        onEnter(args) {
            const fileName = Memory.readCString(args[0]);
            console.log(`[*] fopen: ${fileName}!`)

            // 有的so的maps是先拿到pid再寻找的，不是直接用的self  
            if (fileName && fileName.includes("/proc/self/maps") 
                || (fileName.includes("/proc/") && fileName.includes("/maps"))
            ) {
                console.warn(`[!] Redirecting ${fileName} to /dev/null`);
                args[0] = Memory.allocUtf8String("/dev/null");
            }
        }
    });
}


// hook_monitor_maps_redirect(); // 有的手机需要打开这个才行
hook_dlopen(); // msa, 梆梆nop关键线程函数
