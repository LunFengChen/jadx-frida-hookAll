/**
 * jni函数相关的hook，已经有很成熟的工具了，这就是jnitrace，他帮我们实现了hook以及对于java对象的打印优化，免去我们自己深入学习jni所需的时间；
 * 
 * 
 * jnitrace的使用
 * `jnitrace` 是一个基于 Frida 的工具，专门用于追踪 JNI API 的调用。
 * 可以自动解析 JNI 函数的参数（如把 jstring 转为可读字符串，把 jmethodID 转为方法签名, jbyte 的转换）。
 *
 * [安装]
 * pip install jnitrace
 *
 * [基本使用]
 * jnitrace -l <so_name> <package_name>
 * 示例: jnitrace -l libnative-lib.so com.example.myapp
 *      (追踪 com.example.myapp 中 libnative-lib.so发生的所有 JNI 调用)
 *
 * [常用参数]
 * -l, --libraries <libs>   指定要监控的 SO 库 (支持通配符 *)
 * -i, --include <regex>    只包含方法名匹配正则的调用 (如: "FindClass|GetMethodID")
 * -e, --exclude <regex>    排除匹配正则的调用
 * --hide-data              不显示具体的参数数据 (hex dump)
 *
 * [高级技巧]
 * jnitrace 还可以追踪内存读写，但会比较慢。通常用于分析混淆严重的 SO。
 */



/**
 * 接下来我们放一些我自己对于jnitrace的源码分析
 * 源码仓库: https://github.com/chame1eon/jnitrace
 * 
 * jnitrace 源码分析 (基于 jnitrace-engine)
 * ============================================================================
 * `jnitrace` 的强大之处在于它不仅仅是 Hook，而是构建了一个中间层来实现对目标 SO 的完全隔离监控。
 * 以下分析基于 `jnitrace-engine` (https://github.com/chame1eon/jnitrace-engine)
 *
 * 1. 核心架构：Shadow JNIEnv (影子环境)
 * ----------------------------------------------------------------------------
 * 这是解决性能崩溃和过滤调用来源的核心技术。
 *
 * [源码位置]: 
 * - `src/jni/jni_env_interceptor.ts` (核心类: JNIEnvInterceptor)
 * - `lib/engine.ts` (入口逻辑)
 *
 * [实现逻辑]:
 * 1. **Hook dlopen**: 在 `lib/engine.ts` 中，Hook 了 `dlopen` 和 `android_dlopen_ext`。
 *    - 当监测到目标 SO 加载时，它会进一步 Hook 该 SO 的 `JNI_OnLoad` 函数。
 * 
 * 2. **拦截 JNI_OnLoad**: 
 *    - 当目标 SO 调用 `JNI_OnLoad(JavaVM* vm, void* reserved)` 时，回调进入 `engine.ts`。
 *    - **关键动作**: 它不会把真实的 `vm` 传给 SO，而是传入一个 **ShadowJavaVM**。
 *      `args[0] = shadowJavaVM.handle;`
 *
 * 3. **构建 Shadow JNIEnv**: (`src/jni/jni_env_interceptor.ts`)
 *    - 类 `JNIEnvInterceptor` 负责创建影子环境。
 *    - 它分配一块内存作为新的 `JNIEnv` 结构体。
 *    - 它遍历标准 JNIEnv 的所有函数指针（200+个）。
 *    - 对于每个函数（如 `FindClass`），它生成一个 **Trampoline (跳板)** 函数。
 *      `this.jniEnv.writePointer(addr);` (写入跳板地址)
 *
 * 4. **隔离执行**: 
 *    - 目标 SO 以为自己拿到了真实的 JNIEnv，但实际上调用任何 JNI 函数都会先跳到 `jnitrace` 的跳板函数。
 *    - 跳板函数记录日志、解析参数，然后再调用系统真实的 JNI 函数。
 *    - 系统的其他模块（如 Framework）依然使用真实的 JNIEnv，互不影响。
 *
 * 2. 复杂的参数解析 (Serialization)
 * ----------------------------------------------------------------------------
 * [源码位置]: `src/jni/jni_method_callbacks.ts`
 *
 * - [问题]: Native 函数传入的 `jobject`, `jstring`, `jmethodID` 只是内存地址，人类不可读。
 * - [解决方案]: 在回调中实时解析。
 *
 * - **方法签名解析**:
 *   当 Hook 到 `CallObjectMethod(env, obj, methodID, ...)` 时：
 *   1. 利用 `jmethodID` 调用真实 JNI 的 `ReflectMethod` 或读取内部结构，获取方法签名 (e.g., `Ljava/lang/String;->getBytes()[B`)。
 *   2. 解析签名中的参数类型。
 *   3. 根据参数类型，从 `va_list` 或寄存器中读取对应的值。
 *
 * - **对象内容打印**: (`src/utils/reference_manager.ts`)
 *   维护 `jobject` 到 Java 对象的引用。对于 `String` 等常见类型，直接调用 Java 层的 `toString()` 获取内容并打印。
 *
 * 3. 内存访问监控 (Memory Tracking)
 * ----------------------------------------------------------------------------
 * [源码位置]: `src/jni/jni_method_callbacks.ts`
 *
 * 对于 `GetStringUTFChars`, `GetByteArrayElements` 这类返回指针的函数：
 * 1. `jnitrace` 拦截返回的指针地址。
 * 2. 使用 `Process.setExceptionHandler` 或 `MemoryAccessMonitor` (Frida API) 监控该内存区域。
 * 3. 当 Native 代码尝试读写该内存时，触发异常/回调，从而记录下“Native 层修改了 Java 字符串”这样的行为。
 *
 * 4. 总结
 * ----------------------------------------------------------------------------
 * jnitrace 的核心壁垒在于那套完整的 **Shadow JNIEnv** 构建逻辑和 **类型推断** 算法。
 * 它不仅是 "Hook"，更像是一个 "中间人攻击" (Man-in-the-Middle)，完全接管了 Native 层与 Java 虚拟机的所有通信。
 */




