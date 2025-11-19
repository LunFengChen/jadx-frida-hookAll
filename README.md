# JADX Frida HookAll Plugin

一个简单但实用的 JADX 插件，提供涉及到 Java 层的常用 Frida Hook 脚本，每天帮助你省5分钟翻笔记的时间；

组合快捷键 `Ctrl+Alt+H` 调出树形结构展示ui，提供复制剪切板和切换语言功能，实用且美观；
> 对你有用的话给个star吧或者分享一下，感谢哇；

希望有更多人能加入到这个项目中，一起完善 Frida Hook 脚本仓库；欢迎提 issue 或者 pr；

> 当脚本足够多和完善的时候，对于新手或者老手都非常有用呢；

## 1. 脚本分类

插件提供 **7 大分类**，共 **36 个**常用 Frida Hook 脚本：

| 分类 | 英文名称 | 中文名称 | 脚本数 | 说明 |
|------|---------|---------|--------|------|
| 1️⃣ | **Frida Basics** | Frida基本使用 | 1 | Hook示例和基础用法 |
| 2️⃣ | **Helper Functions** | 辅助函数 | 7 | 打印堆栈、参数、Map等工具函数 |
| 3️⃣ | **Hook JDK** | Hook JDK | 11 | 监控String、Base64、File等JDK类 |
| 4️⃣ | **Hook Android** | Hook Android | 10 | 监控Activity、Dialog、Toast等 |
| 5️⃣ | **Hook Third-Party** | Hook第三方库 | 2 | 监控OkHttp、JSONObject等 |
| 6️⃣ | **Hook JNI** | JNI相关 | - | JNI函数和Native方法hook |
| 7️⃣ | **Frida Advanced** | Frida进阶 | 4 | ClassLoader、动态加载DEX等 |

<details>
<summary>📋 点击查看详细脚本列表</summary>

### 1️⃣ Frida Basics（Frida基本使用）
- Hook示例

### 2️⃣ Helper Functions（辅助函数）
- 打印调用栈
- 数据格式转换（字节↔十六进制↔字符串↔Base64）
- 打印方法参数
- 打印Map对象
- 打印字符串数组
- 打印方法签名
- 打印自定义对象

### 3️⃣ Hook JDK（Hook JDK）
- 监控所有Map
- 监控ArrayList
- 监控Base64（Android）
- 监控Base64（Java）
- 监控Collections
- 监控File
- 监控String
- 监控StringBuilder
- 监控StringFactory
- 监控URL
- 打印Map

### 4️⃣ Hook Android（Hook Android）
- 阻止弹窗
- 监控崩溃
- 监控Activity
- 监控Dialog
- 监控EditText
- 监控Log
- 监控SharedPreferences
- 监控TextUtils
- 监控Toast
- 监控WebView

### 5️⃣ Hook Third-Party（Hook第三方库）
- 监控JSONObject
- 监控OkHttp

### 6️⃣ Hook JNI（JNI相关）
> 此分类为预留分类，你可以添加JNI相关的hook脚本

### 7️⃣ Frida Advanced（Frida进阶）
- 主动调用方法
- ClassLoader辅助
- Dump证书
- 动态加载DEX

</details>


## 2. 安装方法

### 方式 1：jadx-cli 安装（最简单）

```bash
# 直接从 GitHub 安装
jadx plugins --install "github:LunFengChen:jadx-frida-hookAll"

# 或者安装到 jadx-gui（如果已运行 jadx-cli）
jadx plugins --install-location "github:LunFengChen:jadx-frida-hookAll"
```

### 方式 2：GUI 安装

**在线安装**：
1. 打开 JADX GUI → `Preferences` → `Plugins`
2. 点击 `Install plugin` 按钮
3. 输入 locationId：`github:LunFengChen:jadx-frida-hookAll`
4. 重启 JADX

**离线安装**：
1. 从 [Releases](https://github.com/LunFengChen/jadx-frida-hookAll/releases) 下载 `jadx-frida-hookall-x.x.x.jar`
2. 在 JADX GUI 中：`Plugins` → `Install plugin` → 选择 JAR 文件
3. 重启 JADX

### 方式 3：手动编译

如果你想修改插件或贡献代码，请查看 [5. 扩展开发](#5-扩展开发) 章节。

> **更新插件**：先卸载旧版本，重启 JADX，再安装新版本。


## 3. 使用方法

### 3.1 打开插件

两种方式：
- **快捷键**：`Ctrl+Alt+H`
- **菜单**：`Plugins` → `Frida实用脚本库` (Frida Script Library)

### 3.2 使用脚本

1. 单击树节点查看脚本
2. 点击"复制脚本"按钮
3. 保存为 `.js` 文件
4. 使用 Frida 加载：

```bash
frida -U -f com.example.app -l hook.js
```

### 3.3 切换语言

- 插件会自动跟随 JADX 的语言设置
- 也可以点击左下角按钮手动切换中英文


## 4. 脚本示例

1. 打印堆栈

    ```javascript
    function showJavaStacks() {
        console.log(Java.use("android.util.Log")
            .getStackTraceString(Java.use("java.lang.Exception").$new()));
    }
    ```

2.  监控 Dialog

    ```javascript
    Java.perform(function() {
        Java.use('android.app.Dialog').show.implementation = function() {
            console.log('[Dialog] show() called');
            showJavaStacks();
            return this.show();
        };
    });
    ```

## 5. 扩展开发

想要添加新脚本或修改插件？只需 3 步！

### 5.1 添加新脚本

以添加"监控 Toast"为例：

#### 步骤 1：创建脚本文件

创建 `src/main/resources/frida-scripts/hook-android/monitor-toast.js`

```javascript
// Monitor Toast messages
// Author: YourName
Java.perform(function() {
    var Toast = Java.use('android.widget.Toast');
    Toast.show.implementation = function() {
        console.log('[Toast] ' + this.mText.value);
        return this.show();
    };
});
```
要求是套上function(){}, 方便复制后快速调用


#### 步骤 2：注册脚本

编辑 `HookAndroid.java`：
```java
public static final ScriptEntry MONITOR_TOAST = new ScriptEntry(
    "Monitor Toast",
    ScriptLoader.loadScript(BASE_PATH + "monitor-toast.js")
);
```

#### 步骤 3：添加到 UI 树

编辑 `FridaScriptDialog.java` 的 `loadScriptTemplates()` 方法：
```java
androidNode.add(createScriptNode(HookAndroid.MONITOR_TOAST));
```

### 5.2 编译插件

#### 准备 JADX JAR

编译需要 JADX 的 JAR 文件：
- **JADX 源码**：`jadx/jadx-gui/build/libs/jadx-gui-dev-all.jar`
- **已安装的 JADX**：`~/.local/share/jadx/lib/jadx-gui-*.jar`（Linux）
- **下载发布版或者二改版**：
    - https://github.com/skylot/jadx/releases
    - https://github.com/LunFengChen/jadx/releases

#### Windows 编译

```powershell
# 使用默认路径
.\compile.ps1

# 或指定 JAR 路径
.\compile.ps1 "C:\path\to\jadx-gui.jar"
```

#### Linux/Mac 编译

```bash
chmod +x compile.sh

# 自动查找
./compile.sh

# 或指定路径
./compile.sh /path/to/jadx-gui.jar
```

生成的插件：`target/jadx-frida-hookall-1.0.0.jar`

### 5.3 项目结构

```
src/main/
├── java/com/frida/jadx/
│   ├── JadxFridaHookAll.java      # 插件入口
│   ├── FridaScriptDialog.java     # UI 对话框
│   ├── PluginConfig.java          # 配置管理
│   └── templates/
│       ├── HelperFunctions.java   # 辅助函数
│       ├── HookJDK.java
│       ├── HookAndroid.java
│       └── FridaAdvanced.java
└── resources/frida-scripts/
    ├── helpers/
    ├── hook-jdk/
    ├── hook-android/
    └── frida-advanced/
```

### 5.4 发布新版本

#### 自动发布

本项目使用 GitHub Actions 自动发布，只需推送 tag：

```bash
# 创建版本 tag
git tag -a v1.0.1 -m "Release version 1.0.1"

# 推送 tag
git push origin v1.0.1
```

GitHub Actions 会自动编译并发布到 Releases，用户可直接通过 jadx-cli 安装：

```bash
jadx plugins --install "github:LunFengChen:jadx-frida-hookAll"
```

详细发布流程请查看 [RELEASE.md](RELEASE.md)

### 5.5 贡献方式

- **提交 PR**：https://github.com/LunFengChen/jadx-frida-hookAll
- **反馈交流**：Q群 686725227
- **添加脚本**：欢迎提交实用的 Frida Hook 脚本


## 6. 常见问题

**Q: 快捷键不生效？**
- 确保 JADX 窗口处于激活状态
- 或使用菜单：`Plugins` → `Frida实用脚本库` (Frida Script Library)

**Q: 如何切换语言？**
- 插件自动跟随 JADX 语言设置
- 或点击左下角按钮手动切换

## 许可证
Apache 2.0 License
