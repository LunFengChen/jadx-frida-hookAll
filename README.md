# JADX Frida HookAll Plugin

## 💡 项目初衷

在安卓逆向过程中，编写 Frida 脚本是一件很简单但比较耗时的过程。有没有什么办法能节省时间、体验又好呢？

## 🎯 解决方案
两个方案结合使用，可以大大提高逆向效率。
### 方案 1：使用改进版 [jadx-gui](https://github.com/LunFengChen/jadx)

- **F 键**：一键生成 Hook 的 JS 代码，自动识别参数类型，提供常用辅助函数
- **H 键**：一键生成 主动调用+rpc 的 JS 代码，自动识别部分参数类型，辅助构造

### 方案 2：使用本项目的 JADX 插件

- **Ctrl+Alt+H**：一键调出常用脚本库
- **8 大分类**：持续完善中（目前包含常用 59 个脚本）

## ✨ 插件达到的效果

- 🚀 **真一键**：直接 Copy，丢入 Frida 控制台或自建脚本
- 🎯 **省心省力**：帮你做完全部体力活，你只需要动脑
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

脚本主要来自笔者日常逆向工作的总结和积累，部分参考了网络上的公开资料。

由于传播链路较长，部分脚本的最终来源已无法考证，在此向原作者致谢。如有版权问题，请联系我删除或添加署名。

## 💬 反馈与交流

- **提交 Issue**：发现 Bug 或有建议？前往 [GitHub Issues](https://github.com/LunFengChen/jadx-frida-hookall/issues)
- **贡献脚本**：欢迎贡献更多实用脚本！
  1. 将 `.js` 脚本添加到 [`frida-scripts`](https://github.com/LunFengChen/jadx-frida-hookall/tree/master/src/main/resources/frida-scripts) 对应分类目录
  2. 在 [`templates`](https://github.com/LunFengChen/jadx-frida-hookall/tree/master/src/main/java/com/frida/jadx/templates) 中注册脚本
  3. 在 [`FridaScriptDialog.java`](https://github.com/LunFengChen/jadx-frida-hookall/blob/master/src/main/java/com/frida/jadx/FridaScriptDialog.java) 中添加到 UI 树
  4. 提交 Pull Request
- **QQ 交流群**：686725227

## 📄 许可证

MIT License
