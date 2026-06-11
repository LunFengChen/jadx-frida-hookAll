// 静态注册直接看so的exports需要有Java_开头

// 动态注册一般来说ida也能看，但是如果混淆或者加密了，不好看
// 所以可能需要 hook RegisterNatives才能知道
function findJNIfunc_byClassName(targetClassName) {
    // 动态注册大概率经过 RegisterNatives, 而这个在 libart.so 中
    // 1. 在 libart.so 中找 RegisterNatives 地址
    let symbols_libart = Module.enumerateSymbolsSync("libart.so");
    var address_RegisterNatives;
    /* 
    不同安卓版本由于C++名称粉碎(name mangling)，函数名会添加额外字符, 所以需要写一个筛选策略来稳定找到对应的函数
        1) 总结发现都有 art, JNI , RegisterNatives， 这是因为C++的类+函数名决定的
            _ZN3art3JNIILb0EE15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi
        2) 需要去除 CheckJNI
            _ZN3art12_GLOBAL__N_18CheckJNI15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi.llvm.11432704867267263295
    */
    for (const symbol of symbols_libart) {
        // 筛选条件：包含art、JNI、RegisterNatives，但不包含CheckJNI
        if (symbol.name.includes("art")
            && symbol.name.includes("JNI")
            && symbol.name.includes("RegisterNatives")
            && !symbol.name.includes("CheckJNI")
        ) {
            address_RegisterNatives = symbol.address;
            console.warn(`[*] found RegisterNative! ${address_RegisterNatives}, ${symbol.name}`);
            break;
        }
    }
    if (!address_RegisterNatives) {
        console.error(`[x] not found RegisterNative!`);
        return;
    }

    // 2. hook 这个函数获取到注册信息
    /* 在JNI中这个函数的定义如下
    jint RegisterNatives(JNIEnv *env, jclass clazz, const JNINativeMethod *methods, jint nMethods);
        env: JNI 环境指针
        clazz: Java 类对象
        methods: JNI 原生方法数组
        nMethods: 方法数量
    
    我们关心 JNINativeMethod 类型的 数组，里面有我们要的信息； 结构体定义如下
        typedef struct {
            const char *name;      // 方法名, 这里不能说字符串直接放这里，万一摆不下怎么办，所以这里实际上是一个字符串指针，指向真正的字符串地址; frida脚本 为了兼容, Process.pointerSize
            const char *signature; // 方法签名, 同上; 所以实际上也是一个  Process.pointerSize
            void *fnPtr;          // 原生函数指针, 函数地址肯定是一个指针; 所以实际上也是一个  Process.pointerSize
        } JNINativeMethod;
    在这里面我们都需要关心;
    
    我们拿到数组指针后怎么遍历拿到每一个方法的指针呢？
    a) 我们知道了方法数量
    b) 我们知道每个方法的偏移就行了

    每个方法内部字段的偏移呢?
        1) name: 方法基地址，
        2) signature: 方法基地址 + Process.pointerSize;
    */
    let foundMethods = []; // 保存找到的类的所有方法
    Interceptor.attach(address_RegisterNatives, {
        onEnter: function (args) {
            let env = Java.vm.tryGetEnv(); // 这里env的获取我们直接使用 frida-java-bridge 提供的
            let clazz_name = env.getClassName(args[1]); // args[1]: clazz, 要从jclass获取类名需要利用env->getClassName()
            let methods = ptr(args[2]); // args[2]: methods, 方法数组, 拿到指针就行
            let nMethods = args[3].toInt32(); // args[2]: nMethods, 方法数量, 直接转数字

            // 拿到方法数组之后, 我们要知道这个结构体的偏移才能读到对应的字段指针
            // 前面分析了, 每一个方法占三个指针
            for (let i = 0; i < nMethods; i++) {
                let baseAddress_method = methods.add(i * Process.pointerSize * 3);

                // 每个方法结构体的三个字段
                let name = Memory.readCString(baseAddress_method.readPointer());
                let signature = Memory.readCString(baseAddress_method.add(Process.pointerSize).readPointer());
                let fnPtr = baseAddress_method.add(Process.pointerSize * 2).readPointer();
                
                // 如果没有传目标类，则是undefined，则全部打印；否则就只打印目标类
                if (!targetClassName || targetClassName === clazz_name) {
                    var module = Process.findModuleByAddress(fnPtr); // 根据函数地址，从内存中找到对应的so模块
                    const offset_method = fnPtr.sub(module.base); // 计算一下方法相对so的偏移, 因为ida中模块地址是0; 内存中模块起始地址不定，但是函数地址相对so固定
                    console.log(JSON.stringify({
                        "class_name": clazz_name,
                        "name&signature": `${name}${signature}`,
                        "which_so": module.name,
                        "func_offest": offset_method
                    }, null, 2))// 这里利用JSON打印，看着舒服一点
                }
            }
        },
        onLeave: function (retval) { }
    });
    return foundMethods;
}
findJNIfunc_byClassName("com.xunmeng.pinduoduo.secure.DeviceNative"); // 限制类
// findJNIfunc_byClassName(); // 不限制类

// frida -U -f com.xunmeng.pinduoduo -l 01-hook-register-natives.js