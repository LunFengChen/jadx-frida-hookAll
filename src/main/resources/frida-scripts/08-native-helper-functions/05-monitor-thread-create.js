function hook_pthread_create() {
    /* 现在这个基本都不用了，因为太上层了，很多加固厂商调用clone或者直接svc0调用clone系统调用创建线程了；但是学习意义还是有的；

    int pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine) (void *), void *arg);
        thread：指向 pthread_t 类型的指针，用于存储新线程的标识符（线程ID）。
        attr：指向 pthread_attr_t 结构的指针，用于指定线程的属性。如果为 NULL，则使用默认属性。
        start_routine：线程函数的指针，即线程开始执行的函数。这个函数必须返回 void* 并接受一个 void* 参数。
        arg：传递给线程函数的参数，类型为 void*。如果需要传递多个参数，可以将它们封装在一个结构体中，然后传递该结构体的指针。
    */
    var pthread_create_addr = Module.findExportByName("libc.so", "pthread_create");
    console.warn("[*] pthread_create addr: ", pthread_create_addr);
    Interceptor.attach(pthread_create_addr, {
        onEnter: function (args) {
            var thread_func_addr = args[2];
            var module = Process.findModuleByAddress(thread_func_addr);
            console.log(`[*] pthread_create thread func: ${module.name}! 0x${(thread_func_addr - module.base).toString(16)}`);
        }, onLeave: function (retval) {
        }
    });
}

function hook_monitor_clone() {
    /* 这个用的很多, 一般都会用到; 如果没效果，是因为基本检测还没过；

    int clone(int (*fn)(void *), void *stack, int flags, void *arg, ...);
    pthread_create内部调用clone, 然后pthread_create传入的线程函数地址在其第3个参数
    然后我们看libc.so中的pthread_create函数实现，可以看到其调用了clone系统调用, a3参数传入的就是线程函数地址
    *(v30 + 96) = a3
    所以我们hook clone，要拿到这里的v30, 然后再加96偏移读取出线程函数地址
    v36 = clone(__pthread_start, v19, 4001536, v30, v30 + 16, v23 + 8, v30 + 16);
    而v30是clone的第四个参数
    */
    var clone = Module.findExportByName('libc.so', 'clone');
    Interceptor.attach(clone, {
        onEnter: function(args) {
            if (args[3] == 0) return;
            
            try {
                var fn = args[3].add(96).readPointer(); // 线程函数地址
                var module = Process.findModuleByAddress(fn); // 寻找模块
                if (module) {
                    var offset = fn.sub(module.base).toString(16);
                    console.log(`[Clone] ${module.name} + 0x${offset}`);
                } else{
                    console.log(`[Clone] anonymous memory! fn addr: ${fn}`); // 这里可以dump匿名内存+whichSo找到正确偏移地址
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

hook_monitor_clone(); // 找到函数之后对目标线程检测函数进行置空

