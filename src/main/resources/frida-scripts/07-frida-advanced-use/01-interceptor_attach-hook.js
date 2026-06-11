// func_address: 你要hook的native函数地址
Interceptor.attach(func_address, {
    onEnter: function (args) { // 函数进入时触发
        console.log(`-------------> enter: 0x${func_address.toString(16)}`);
        // 1. 打印参数
        // 1) 先看是否是指针
        console.log(`args[0] is at ${args[0]}, args[1] is at ${args[1]}, args[2] is at ${args[2]}, args[3] is at ${args[3]}`);
        console.log(`args[0] (hex):\n${hexdump(args[0])}`); // 如果是指针就能直接hexdump

        // 2) 如果是常用类型可以调用api获得更清楚的打印效果
        // a) 如果是cstring
        console.log(`args[0] (char*): ${args[0].readCString()}`);
        // b) 如果是整数
        console.log(`args[0] (int32): ${args[0].readInt()}`);
        // console.log(`args[0] (int32): ${args[0].toInt32()}`);

        // 3. 如果要替换值
        args[0] = ptr("111"); // 要用ptr包裹


        // 4. 如果要保存数据给leave使用, 使用this
        this.arg0 = args[0]; // 注意只能保存变量，数组不可以
    }, 
    onLeave: function (retval) { // 函数退出时触发
        // 打印返回值
        console.log(`retval is at ${retval}`);
        // 修改返回值
        // a) 整数类型
        retval.replace(1); // 替换返回值为1
        // b) bool类型
        retval.replace(ptr(0x1)); // ptr(0x0)
        // c) 字符串类型
        retval.replave(Java.vm.getEnv().newStringUtf("1234")); // 利用frida-java-bridge的


        console.log(`<------------- enter: 0x${func_address.toString(16)}`);
    }
});
