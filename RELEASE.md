# 发布新版本指南

## 自动发布流程

本项目使用 GitHub Actions 自动发布插件，流程如下：

### 1. 准备发布

确保所有代码已提交并推送到 GitHub：
```bash
git add .
git commit -m "Release version x.x.x"
git push origin main
```

### 2. 创建并推送 Tag

```bash
# 创建 tag（版本号格式：v1.0.0）
git tag -a v1.0.0 -m "Release version 1.0.0"

# 推送 tag 到 GitHub
git push origin v1.0.0
```

### 3. 自动构建

GitHub Actions 会自动：
- ✅ 检出代码
- ✅ 下载 JADX GUI JAR
- ✅ 编译插件
- ✅ 创建 GitHub Release
- ✅ 上传插件 JAR 文件
- ✅ 生成发布说明

### 4. 验证发布

发布完成后，验证安装：

```bash
# 使用 jadx-cli 安装测试
jadx plugins --install "github:LunFengChen:jadx-frida-hookAll"

# 检查插件列表
jadx plugins --list
```

或在 JADX GUI 中测试：
1. 打开 `Preferences` → `Plugins`
2. 点击 `Install plugin`
3. 输入：`github:LunFengChen:jadx-frida-hookAll`
4. 验证能否正确下载和安装

## 手动发布流程

如果自动发布失败，可以手动发布：

### 1. 本地编译

```bash
# Windows
.\compile.ps1

# Linux/Mac
./compile.sh
```

### 2. 创建 GitHub Release

1. 进入 GitHub 仓库
2. 点击 `Releases` → `Create a new release`
3. 创建新 tag：`v1.0.0`
4. 上传 `target/jadx-frida-hookall-1.0.0.jar`
5. 填写发布说明

### 3. JAR 文件命名规范

⚠️ **重要**：Release 中的 JAR 文件名必须严格遵循格式：

```
<repo-name>-<version>.jar
```

例如：
- ✅ `jadx-frida-hookall-1.0.0.jar`
- ✅ `jadx-frida-hookall-1.0.1.jar`
- ❌ `jadx-frida-hookAll-1.0.0.jar` (大小写错误)
- ❌ `frida-hookall-1.0.0.jar` (名称不匹配)

## 版本号规范

使用语义化版本号（Semantic Versioning）：

```
<major>.<minor>.<patch>

major: 重大更新，可能有不兼容改动
minor: 新功能，向后兼容
patch: Bug 修复，向后兼容
```

示例：
- `1.0.0` - 首次发布
- `1.0.1` - Bug 修复
- `1.1.0` - 新增功能
- `2.0.0` - 重大更新

## 添加到 JADX 社区插件列表（可选）

如果想让插件更容易被发现，可以将插件添加到 JADX 官方社区列表：

1. Fork 仓库：https://github.com/jadx-decompiler/jadx-plugins-list
2. 编辑 `plugins-list.json`，添加插件信息：
```json
{
  "locationId": "github:LunFengChen:jadx-frida-hookAll",
  "name": "Frida HookAll",
  "description": "Frida Hook script templates for Java/Android reverse engineering",
  "homepage": "https://github.com/LunFengChen/jadx-frida-hookAll"
}
```
3. 提交 PR

## 发布检查清单

发布前检查：
- [ ] 所有测试通过
- [ ] README.md 已更新
- [ ] 版本号已更新（pom.xml）
- [ ] CHANGELOG 已更新（如果有）
- [ ] 所有代码已提交
- [ ] Tag 版本号正确

发布后验证：
- [ ] GitHub Release 创建成功
- [ ] JAR 文件已上传
- [ ] JAR 文件名格式正确
- [ ] jadx-cli 能正确安装
- [ ] jadx-gui 能正确安装
- [ ] 插件功能正常

## 常见问题

**Q: 为什么 jadx 无法从 GitHub 安装插件？**

A: 检查：
1. JAR 文件名格式是否正确：`jadx-frida-hookall-<version>.jar`
2. Release 是否为公开（Public）
3. JAR 文件是否成功上传到 Release Assets

**Q: 如何回滚到旧版本？**

A: 用户可以指定版本安装：
```bash
jadx plugins --install "github:LunFengChen:jadx-frida-hookAll:1.0.0"
```

**Q: GitHub Actions 编译失败怎么办？**

A: 
1. 查看 Actions 日志
2. 确保 JADX GUI JAR 下载链接有效
3. 必要时使用手动发布流程
