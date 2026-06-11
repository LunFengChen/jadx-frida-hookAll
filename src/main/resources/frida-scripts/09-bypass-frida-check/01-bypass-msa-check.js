/**
 * 绕过移动安全联盟frida检测的脚本
 * 对应的so是libmsaoaidsec.so(最稳的是linker方案,其余方案在某些设备可用), 旧版本是libsecsdk.so(简单魔改特征或者置空so就行)
 */

function hook_dlopen() {
    Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"), {
        onEnter: function (args) {
            this.fileName = args[0].readCString();
            console.log(`[+] dlopen onEnter ==> ${this.fileName}`);
            // msa: 干掉入口函数
            if (this.fileName && this.fileName.includes("libmsaoaidsec.so")) {
                console.warn(`[+] dlopen onEnter ==> ${this.fileName}`);
                // 测试环境: win11/10, android12/13, rusda16.2.1(抹除一些基础特征) + 本脚本即可绕过； 如果是比较强的魔改server, 不需要本脚本；
		        // 某些server绕不了：比如florida配合脚本依然被检测到

                // 通用1: 杀入口函数(很稳定)
                // msa是一个比较固定的sdk, 版本更迭慢, 最近的版本入口函数固定不变
                hook_call_constructors_bypass_msa();

                // 通用2: 空替换(小部分情况不稳定)
                // args[0] = replace_loadso(args[0], "");

                // 通用3: 重定向libc, 这里是后者(小部分情况不稳定)
                // args[0] = replace_loadso(args[0], "libc.so");


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
        // 模糊匹配：只要包含 soinfo 和 call_constructors 就是目标
        // 这种策略比使用粉碎后的全名匹配更稳健，适应不同Android版本
        if (symbol.name.includes("soinfo") && symbol.name.includes("call_constructors")) {
            address_call_constructors = symbol.address;
            console.warn(`[*] Found symbol: ${symbol.name}`);
            break;
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
    return Memory.allocUtf8String(replace_libname);
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
hook_dlopen(); // msa绕过
