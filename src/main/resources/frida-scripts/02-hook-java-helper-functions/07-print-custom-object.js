// 功能：打印对象 - 解决 Frida 中 [Object object] 问题
function showJavaObject(obj) {
    // JSON.stringify 序列化 查看类和具体实例
    console.log(JSON.stringify(obj).toString());
    // 然后可以使用 Java.cast 转为 Java 对象 再打印
    // console.log(Java.cast(obj, Java.use("xxx")).toString());
}

/*
关于 打印对象 (Print Object) 的详解

Frida 中会遇到两种对象：
1. **Java 对象**: 直接打印显示类名和地址，如 `com.example.User@1a2b3c`
2. **JavaScript 对象**: frida有时会拿到 JavaScript 包装对象，无法看到内容

问题根源：
- Java 对象: `console.log(obj)` 调用的是 Java 的 `toString()`
- JavaScript 对象: `console.log(obj)` 只显示类型，不显示内容

解决方案：
1. JavaScript 对象:
   - 使用 `JSON.stringify(obj)` 序列化为 JSON
   - 就能看到 className、instanceName 等所有属性
   - 此时再用 `Java.cast` 转换为具体 Java 对象类型以获得更详细信息

2. Java 对象:
   - 如果 toString() 输出不够详细，用 `Java.cast` 转为正确类型
   - 转换后的对象 toString() 通常会显示更多信息
   - 或者用 `printJavaObjectFields()` 反射查看所有字段，然后自己写一个详细的打印函数

*/
