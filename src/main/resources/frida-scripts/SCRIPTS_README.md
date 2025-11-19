# Frida Scripts 脚本说明

本目录包含所有Frida Hook脚本，按功能分类组织。

## 📁 目录结构

### 🔧 helpers/ - 辅助函数
基础的打印和数据处理函数

- `print-stacktrace.js` - 打印Java堆栈
- `print-args.js` - 打印方法参数
- `bytes-to-hex.js` - 字节转十六进制
- `print-method-signature.js` - 打印方法签名
- `print-map-gson.js` - 使用Gson打印Map
- `print-map-iterate.js` - 遍历打印Map
- `print-bytes-utf8.js` - 字节转UTF-8字符串
- `print-string-array.js` - 打印字符串数组
- `print-custom-object.js` - 打印自定义对象

### 📦 hook-jdk/ - JDK API监控
监控Java标准库的常用类

- `print-map.js` - 打印Map内容（简单版）
- `monitor-all-map.js` - 监控所有Map操作（完整版）
- `monitor-base64-android.js` - 监控Android Base64编解码
- `monitor-base64-java.js` - 监控Java Base64编解码
- `monitor-arraylist.js` - 监控ArrayList操作
- `monitor-string.js` - 监控String操作
- `monitor-stringfactory.js` - 监控String构造
- `monitor-stringbuilder.js` - 监控StringBuilder/StringBuffer
- `monitor-url.js` - 监控URL请求
- `monitor-collections.js` - 监控Collections.sort
- `monitor-file.js` - 监控文件读写

### 📱 hook-android/ - Android API监控
监控Android框架的常用API

- `monitor-dialog.js` - 监控Dialog弹窗
- `monitor-toast.js` - 监控Toast消息
- `monitor-textutils.js` - 监控TextUtils.isEmpty
- `monitor-edittext.js` - 监控EditText输入
- `monitor-log.js` - 监控Android Log输出
- `monitor-sharedpreferences.js` - 监控SharedPreferences和ContentResolver
- `monitor-webview.js` - 监控WebView（开启调试、监控URL）
- `monitor-activity.js` - 监控Activity页面切换
- `hook-crash.js` - 拦截App闪退
- `block-popup.js` - 拦截所有弹窗（WindowManager底层）

### 🔌 hook-third-party/ - 第三方库监控
监控常用的第三方库

- `monitor-okhttp.js` - 监控OkHttp请求（拦截器、Header、URL）
- `monitor-jsonobject.js` - 监控JSONObject操作（重要：处理请求体和响应体）

### 🎯 hook-basics/ - 基础Hook示例
基本的Hook技巧和示例

- `hook-examples.js` - Hook基础示例（普通方法、重载、构造函数、字段、内部类、枚举类）

### 🚀 active-call/ - 主动调用
Java层主动调用方法的示例

- `call-methods.js` - 主动调用示例（静态方法、实例方法、各种数据类型处理）

### 🔬 hook-advanced/ - 高级功能
高级Hook技术和工具

- `classloader-helper.js` - ClassLoader处理（寻找、设置、加壳处理）
- `dump-certificate.js` - 证书自吐（从KeyStore提取证书）
- `load-dex.js` - 加载外部DEX文件

### ⚡ frida-advanced/ - Frida高级API
Frida框架的高级功能

- `jni-register-natives.js` - JNI RegisterNatives监控

## 🎨 使用方法

### 1. 直接使用单个脚本
```bash
frida -U -f com.example.app -l hook-jdk/monitor-string.js
```

### 2. 组合多个脚本
```bash
frida -U -f com.example.app -l helpers/print-stacktrace.js -l hook-jdk/monitor-map.js
```

### 3. 在JADX插件中使用
1. 打开JADX GUI
2. 按 `Ctrl+Alt+H` 调出插件窗口
3. 选择需要的脚本
4. 点击"复制脚本"按钮
5. 保存为.js文件并使用Frida加载

## 💡 脚本分类说明

### 按使用场景分类

**🔍 逆向分析场景**
- 请求分析：`monitor-okhttp.js`, `monitor-url.js`, `monitor-jsonobject.js`
- 响应分析：`monitor-jsonobject.js`, `monitor-base64-*.js`
- 加密分析：`monitor-base64-*.js`, `monitor-string.js`, `dump-certificate.js`
- 流程分析：`print-stacktrace.js`, `monitor-activity.js`

**🛡️ 反调试场景**
- 弹窗绕过：`block-popup.js`, `monitor-dialog.js`, `monitor-toast.js`
- 闪退处理：`hook-crash.js`
- WebView调试：`monitor-webview.js`

**🔐 安全测试场景**
- 密码爆破：`monitor-edittext.js`, `monitor-textutils.js`
- 存储分析：`monitor-sharedpreferences.js`, `monitor-file.js`
- 证书提取：`dump-certificate.js`

**⚙️ 加固对抗场景**
- ClassLoader处理：`classloader-helper.js`
- DEX加载：`load-dex.js`
- JNI分析：`jni-register-natives.js`

### 按Hook深度分类

**Level 1 - 基础监控**
- `helpers/` 目录下的所有脚本
- `hook-basics/hook-examples.js`

**Level 2 - API监控**
- `hook-jdk/` 目录下的脚本
- `hook-android/` 目录下的脚本
- `hook-third-party/` 目录下的脚本

**Level 3 - 高级技术**
- `hook-advanced/` 目录下的脚本
- `frida-advanced/` 目录下的脚本
- `active-call/` 目录下的脚本

## 📝 注意事项

1. **性能影响**：某些脚本（如`monitor-string.js`）可能影响性能，需要添加过滤条件
2. **兼容性**：不同Android版本API可能有差异，部分脚本需要调整
3. **权限要求**：某些脚本（如`dump-certificate.js`）需要存储权限
4. **ClassLoader**：加壳App需要使用`classloader-helper.js`处理ClassLoader问题

## 🔄 更新日志

### v1.0.0 (2025-01)
- ✅ 添加40+个实用Hook脚本
- ✅ 按功能分类组织
- ✅ 添加详细注释和使用说明
- ✅ 支持中文注释

## 🤝 贡献

欢迎提交新的Hook脚本！请确保：
- 添加清晰的中英文注释
- 提供使用示例
- 说明适用场景
- 更新本README

## 📮 反馈

- GitHub: https://github.com/LunFengChen/jadx-frida-hookAll
- Q群: 686725227
