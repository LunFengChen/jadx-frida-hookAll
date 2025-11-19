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