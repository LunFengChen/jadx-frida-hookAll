// 功能：打印类的所有方法签名（Java 格式和 Smali 格式）

// 辅助函数: Java 类型转 Smali 类型描述符
function javaTypeToSmali(javaClass) {
    var className = javaClass.getName();
    
    // 处理基本类型
    if (className === "boolean") return "Z";
    if (className === "byte") return "B";
    if (className === "char") return "C";
    if (className === "short") return "S";
    if (className === "int") return "I";
    if (className === "long") return "J";
    if (className === "float") return "F";
    if (className === "double") return "D";
    if (className === "void") return "V";
    
    // 处理数组
    if (className.startsWith("[")) {
        return className.replace(/\./g, "/");
    }
    
    // 处理对象类型
    return "L" + className.replace(/\./g, "/") + ";";
}

// 辅助函数: 获取 Smali 方法签名
function getSmaliSignature(method) {
    var paramTypes = method.getParameterTypes();
    var returnType = method.getReturnType();
    
    var signature = "(";
    for (var i = 0; i < paramTypes.length; i++) {
        signature += javaTypeToSmali(paramTypes[i]);
    }
    signature += ")";
    signature += javaTypeToSmali(returnType);
    
    return signature;
}

// 方法1: 打印所有方法的 Java 签名
function showMethodJavaSignature(clazz){
    var methods = clazz.class.getDeclaredMethods();
    console.log("=== Java Signatures ===");
    for (var i = 0; i < methods.length; i++) {
        var methodName = methods[i].getName();
        var methodSignature = methods[i].toString();
        console.log("[" + i + "] " + methodSignature);
    }
}

// 方法2: 打印所有方法的 Smali 签名
function showMethodSmaliSignature(clazz){
    var methods = clazz.class.getDeclaredMethods();
    console.log("=== Smali Signatures ===");
    for (var i = 0; i < methods.length; i++) {
        var methodName = methods[i].getName();
        var smaliSignature = getSmaliSignature(methods[i]);
        console.log("[" + i + "] " + methodName + smaliSignature);
    }
}

// 方法3: 同时打印 Java 和 Smali 签名
function showAllSignatures(clazz){
    var methods = clazz.class.getDeclaredMethods();
    console.log("=== All Method Signatures ===");
    for (var i = 0; i < methods.length; i++) {
        var methodName = methods[i].getName();
        var javaSignature = methods[i].toString();
        var smaliSignature = getSmaliSignature(methods[i]);
        console.log("[" + i + "] " + methodName);
        console.log("    Java:  " + javaSignature);
        console.log("    Smali: " + methodName + smaliSignature);
    }
}

// 注意事项：
// 1. Smali 签名格式: 方法名(参数类型...)返回类型
// 2. 基本类型: I=int, J=long, Z=boolean, F=float, D=double, V=void, B=byte, C=char, S=short
// 3. 对象类型: Ljava/lang/String; (以L开头，以;结尾)
// 4. 数组类型: [I=int[], [[I=int[][], [Ljava/lang/String;=String[]

// 使用示例:
// function hook_monitor_printSignatures(){
//     Java.perform(function () {
//         let com_example_YourClass = Java.use("com.example.YourClass");
//         
//         console.log(`[*] Printing all method signatures for com.example.YourClass`);
//         
//         // 打印所有 Java 签名
//         showMethodJavaSignature(com_example_YourClass);
//         
//         // 打印所有 Smali 签名
//         showMethodSmaliSignature(com_example_YourClass);
//         
//         // 同时打印两种签名
//         showAllSignatures(com_example_YourClass);
//     });
//     console.warn(`[*] hook_monitor_printSignatures is injected!`);
// };
// hook_monitor_printSignatures();

/*
关于 打印方法签名 (Print Method Signature) 的详解

Frida Hook 需要精确的重载类型 (Overload)，尤其是当方法有多个同名不同参版本时。
这个脚本能帮你把目标类的所有方法签名都打印出来，方便复制粘贴到脚本里。

两种格式：
1. Java 格式 (`void foo(int, java.lang.String)`):
   - 阅读方便。
2. Smali 格式 (`foo(ILjava/lang/String;)V`):
   - 某些底层 Hook (如 Hook 构造函数 `$init`，或者 Native Hook) 有时会用。
   - 逆向工具 (如 Jadx, IDA) 里显示的通常也是这种。

逆向价值：
- 当你看到错误提示 `Error: expected a pointer, but got a number` 或者 `Error: overload not found` 时。
- 跑一下这个脚本，把打印出来的重载签名复制到 `.overload(...)` 里即可解决。

速记：
1. Hook 报错 "overload"？用这个脚本查一下正确的签名。
2. 这里的 `javaTypeToSmali` 函数本身也是个很好的 Smali 语法参考。
*/