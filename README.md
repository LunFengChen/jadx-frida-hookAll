# JADX Frida HookAll Plugin

## 💡 项目初衷

在安卓逆向过程中，编写 Frida 脚本和翻找写过的脚本是一件很简单但比较耗时的过程。有没有什么办法能节省时间、体验又好呢？

我的想法是找一个安卓逆向必用的工具，然后ui要好，使用丝滑，那么只能是jadx了； 所以我写了个插件，然后把常用的frida脚本都集成进去，相当于一个脚本库；（目前有些脚本是ai写的，可能用不了，后续逐步验证）

如果你对这个仓库的某些脚本不会使用以及看注释还是理解不了，请移步我的BiliBili系列视频，我将会以案例的形式来讲解使用，目标是是做到95%场景的frida脚本；还有就是，不要试图一次性全部学会，而是偶尔多看看加深记忆，hook思路 >> 脚本编写；

## 🎯 解决方案
两个方案结合使用，可以大大提高逆向效率。
### 方案 1：使用本项目的 JADX 插件

- **Ctrl+Alt+H**：一键调出常用脚本库
- **8 大分类**：

### 方案 2：使用改进版 [jadx-gui](https://github.com/LunFengChen/jadx)


- **F 键**：一键生成 Hook 的 JS 代码，自动识别参数类型，提供常用辅助函数
- **H 键**：一键生成 主动调用+rpc 的 JS 代码，自动识别部分参数类型，辅助构造
## ✨ 插件达到的效果

- 🚀 **真一键**：调用快捷键 `Ctrl+Alt+H`(hook) 直接 Copy代码，然后丢入 Frida 控制台或自建脚本
- 🎯 **省心省力**：帮你做完全部体力活，你只需要动脑思考hook点
- 💎 **UI 精美**：双语支持、代码折叠、语法高亮、Copy 可去注释、jadx原生ui

![插件界面预览](image.png)


## 安装方式

### 方式 1：命令行安装（推荐）

```bash
jadx plugins --install "github:LunFengChen:jadx-frida-hookall"
```

### 方式 2：GUI 安装

1. JADX GUI → `Plugins` → `Install plugin`
2. 输入：`github:LunFengChen:jadx-frida-hookall`
3. 重启 JADX

> 📌 **TODO**: 后续将提交到 [JADX 官方插件市场](https://github.com/jadx-decompiler/jadx-plugins-list)，届时可直接在 JADX 中一键安装

## 📚 脚本来源

- 作者日常实战逆向工作的总结和积累
- frida 官方文档
- 网络上的各种公开资料(一般会注释在脚本中)

由于传播链路较长，可能出现部分脚本的最终来源已无法考证，如有版权问题，请联系我删除或添加署名。

## 💬 反馈与交流

- **提交 Issue**：发现 Bug 或有建议？前往 [GitHub Issues](https://github.com/LunFengChen/jadx-frida-hookall/issues) 提交
- **贡献脚本**：欢迎贡献更多实用脚本！
  1. 将 `.js` 脚本添加到 [`frida-scripts`](https://github.com/LunFengChen/jadx-frida-hookall/tree/master/src/main/resources/frida-scripts) 对应分类目录
  2. 在 [`templates`](https://github.com/LunFengChen/jadx-frida-hookall/tree/master/src/main/java/com/frida/jadx/templates) 中注册脚本
  3. 在 [`FridaScriptDialog.java`](https://github.com/LunFengChen/jadx-frida-hookall/blob/master/src/main/java/com/frida/jadx/FridaScriptDialog.java) 中添加到 UI 树
  4. 提交 Pull Request
- **QQ 交流群**：686725227

## 📄 许可证

MIT License
