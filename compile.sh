#!/bin/bash

echo "========== JADX Frida HookAll 编译 =========="

# 从参数或环境变量获取 JADX JAR 路径
if [ -n "$1" ]; then
    JADX_GUI_JAR="$1"
elif [ -n "$JADX_GUI_JAR" ]; then
    JADX_GUI_JAR="$JADX_GUI_JAR"
else
    # 尝试常见路径
    POSSIBLE_PATHS=(
        "$HOME/.local/share/jadx/lib/jadx-gui-*.jar"
        "/usr/share/jadx/lib/jadx-gui-*.jar"
        "/opt/jadx/lib/jadx-gui-*.jar"
        "./jadx-gui*.jar"
    )
    
    for path in "${POSSIBLE_PATHS[@]}"; do
        if ls $path 1> /dev/null 2>&1; then
            JADX_GUI_JAR=$(ls $path | head -n 1)
            break
        fi
    done
fi

# 检查 JADX JAR 是否存在
if [ -z "$JADX_GUI_JAR" ] || [ ! -f "$JADX_GUI_JAR" ]; then
    echo "❌ 错误：未找到 JADX JAR 文件"
    echo ""
    echo "请使用以下方式之一指定 JADX JAR 路径:"
    echo "  1. 参数传递: ./compile.sh /path/to/jadx-gui.jar"
    echo "  2. 环境变量: export JADX_GUI_JAR=/path/to/jadx-gui.jar"
    echo "  3. 将 jadx-gui.jar 放到当前目录"
    echo ""
    echo "常见 JADX JAR 位置:"
    echo "  - ~/.local/share/jadx/lib/jadx-gui-*.jar"
    echo "  - /usr/share/jadx/lib/jadx-gui-*.jar"
    echo "  - JADX 源码: jadx/jadx-gui/build/libs/jadx-gui-dev-all.jar"
    exit 1
fi

echo "✓ 找到 JADX: $JADX_GUI_JAR"

# 检查 Maven 是否安装
if ! command -v mvn &> /dev/null; then
    echo "❌ 错误：未找到 Maven"
    echo "请先安装 Maven: https://maven.apache.org/install.html"
    exit 1
fi

# 步骤 1: 创建 lib 目录并复制 JADX
echo ""
echo "[1/2] 准备 JADX 库..."

mkdir -p lib
cp "$JADX_GUI_JAR" lib/jadx-gui.jar

if [ $? -eq 0 ]; then
    echo "✓ 复制 JADX 库到 lib/jadx-gui.jar"
else
    echo "❌ 复制失败"
    exit 1
fi

# 步骤 2: 编译项目
echo ""
echo "[2/2] 编译项目..."
mvn clean package -DskipTests

if [ $? -eq 0 ]; then
    echo ""
    echo "========================================"
    echo "✓ 编译成功!"
    echo "========================================"
    echo ""
    echo "生成的插件文件:"
    JAR_FILE="target/jadx-frida-hookall-1.0.3.jar"
    if [ -f "$JAR_FILE" ]; then
        SIZE=$(du -h "$JAR_FILE" | cut -f1)
        echo "  路径: $(pwd)/$JAR_FILE"
        echo "  大小: $SIZE"
    fi
    echo ""
    echo "安装到 JADX:"
    echo "  方法1 - GUI 安装:"
    echo "    在 JADX GUI 中: Plugins -> Install plugin -> 选择上面的 jar 文件"
    echo ""
    echo "  方法2 - 命令行安装:"
    echo "    jadx plugins --install-local $JAR_FILE"
    echo ""
else
    echo ""
    echo "========================================"
    echo "❌ 编译失败"
    echo "========================================"
    exit 1
fi
