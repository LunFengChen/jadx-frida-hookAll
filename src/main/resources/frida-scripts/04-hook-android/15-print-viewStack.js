// ============================ Android UI分析工具集 ============================
/** 
 * Android UI分析工具集 - 包含View层级遍历和批量处理功能
 * 整合了dumpViewHierarchy和eachAllView功能
 * 参考： https://juejin.cn/post/7221089899280072763
 */

// 类型定义
const ViewTypes = {
    ViewGroup: 'android.view.ViewGroup',
    View: 'android.view.View'
};

// 回调接口定义
class ViewCallback {
    /**
     * 当匹配到View时调用
     * @param {object} view - Java View对象
     * @param {number} depth - View深度
     * @param {string} path - View路径
     */
    onMatch(view, depth, path) {
        // 子类需要实现此方法
    }
    
    /**
     * 遍历开始时调用
     * @param {object} rootView - 根View对象
     */
    onStart(rootView) {
        // 可选实现
    }
    
    /**
     * 遍历结束时调用
     * @param {number} totalCount - 遍历的View总数
     */
    onFinish(totalCount) {
        // 可选实现
    }
}

/**
 * 简单的打印回调（示例）
 */
class SimplePrintCallback extends ViewCallback {
    onMatch(view, depth, path) {
        const className = getSimpleClassName(view);
        const indent = '  '.repeat(depth);
        console.log(`${indent}├── ${className} (深度: ${depth})`);
    }
    
    onStart(rootView) {
        console.log('🚀 开始遍历View...');
    }
    
    onFinish(totalCount) {
        console.log(`✅ 遍历完成，共 ${totalCount} 个View`);
    }
}

// ============================ 工具函数 ============================

/**
 * 获取View的简单类名
 */
function getSimpleClassName(view) {
    if (!view || !view.$className) return 'Unknown';
    const fullName = view.$className;
    const lastDotIndex = fullName.lastIndexOf('.');
    return lastDotIndex !== -1 
        ? fullName.substring(lastDotIndex + 1)
        : fullName;
}

/**
 * 获取View的资源ID
 */
function getViewId(view) {
    try {
        const id = view.getId();
        if (id === -1) return 'NO_ID';
        
        try {
            const resources = view.getResources();
            const resourceName = resources.getResourceName(id);
            return resourceName || ('0x' + id.toString(16));
        } catch (e) {
            return '0x' + id.toString(16);
        }
    } catch (e) {
        return 'UNKNOWN_ID';
    }
}

/**
 * 检查是否是ViewGroup
 */
function isViewGroup(view) {
    try {
        const ViewGroup = Java.use(ViewTypes.ViewGroup);
        const Class = Java.use('java.lang.Class');
        
        const viewClass = Class.forName(view.$className);
        const viewGroupClass = Class.forName(ViewTypes.ViewGroup);
        
        return viewGroupClass.isAssignableFrom(viewClass);
    } catch (e) {
        console.warn(`检查ViewGroup类型失败: ${e.message}`);
        return false;
    }
}

/**
 * 生成View路径
 */
function generateViewPath(view, depth, parentPath = 'root') {
    const className = getSimpleClassName(view);
    const viewId = getViewId(view);
    const idPart = viewId !== 'NO_ID' ? `[@${viewId}]` : '';
    return `${parentPath}/${className}${idPart}`;
}

// ============================ 核心遍历函数 ============================

/**
 * 遍历所有View（递归内部函数）
 * @param {object} rootView - 根View对象
 * @param {ViewCallback} callback - 回调对象
 * @param {boolean} isRecursion - 是否是递归调用
 * @param {number} depth - 当前深度
 * @param {string} parentPath - 父级路径
 * @param {object} stats - 统计信息
 * @returns {number} 遍历的View总数
 */
function eachAllViewInner(rootView, callback, isRecursion, depth = 0, parentPath = 'root', stats = { count: 0 }) {
    try {
        if (!rootView) {
            console.warn(`深度 ${depth}: 遇到空View`);
            return stats.count;
        }
        
        // 生成当前View的路径
        const currentPath = generateViewPath(rootView, depth, parentPath);
        
        // 执行回调
        try {
            callback.onMatch(rootView, depth, currentPath);
        } catch (e) {
            console.error(`回调执行失败: ${e.message}`);
        }
        
        stats.count++;
        
        // 如果是ViewGroup，递归遍历子View
        if (isViewGroup(rootView)) {
            try {
                const ViewGroup = Java.use(ViewTypes.ViewGroup);
                const viewGroup = Java.cast(rootView, ViewGroup);
                const childCount = viewGroup.getChildCount();
                
                for (let i = 0; i < childCount; i++) {
                    const childView = viewGroup.getChildAt(i);
                    const nextPath = `${currentPath}[${i}]`;
                    
                    if (isViewGroup(childView)) {
                        eachAllViewInner(childView, callback, true, depth + 1, nextPath, stats);
                    } else {
                        // 非ViewGroup直接回调
                        const leafPath = generateViewPath(childView, depth + 1, nextPath);
                        try {
                            callback.onMatch(childView, depth + 1, leafPath);
                        } catch (e) {
                            console.error(`回调执行失败: ${e.message}`);
                        }
                        stats.count++;
                    }
                }
            } catch (e) {
                console.warn(`遍历子View失败: ${e.message}`);
            }
        }
        
        return stats.count;
    } catch (e) {
        console.error(`遍历View时发生错误: ${e.message}`);
        return stats.count;
    }
}

/**
 * 遍历所有View（主函数）
 * @param {object} rootView - 根View对象
 * @param {ViewCallback|Function} callback - 回调对象或函数
 * @param {object} options - 配置选项
 * @returns {number} 遍历的View总数
 */
function eachAllView(rootView, callback, options = {}) {
    const defaultOptions = {
        verbose: false,
        maxDepth: 50
    };
    const config = { ...defaultOptions, ...options };
    
    let callbackObj;
    
    // 处理不同类型的回调
    if (typeof callback === 'function') {
        // 如果是函数，创建一个简单的回调对象
        callbackObj = new ViewCallback();
        callbackObj.onMatch = callback;
    } else if (callback && typeof callback.onMatch === 'function') {
        // 如果已经是回调对象
        callbackObj = callback;
    } else {
        throw new Error('callback必须是一个函数或实现了onMatch方法的对象');
    }
    
    // 开始遍历
    if (callbackObj.onStart) {
        try {
            callbackObj.onStart(rootView);
        } catch (e) {
            console.error(`onStart回调失败: ${e.message}`);
        }
    }
    
    if (config.verbose) {
        console.log(`🌳 开始遍历View树...`);
        console.log(`根View: ${rootView.$className}`);
    }
    
    const stats = { count: 0 };
    const totalCount = eachAllViewInner(rootView, callbackObj, false, 0, 'root', stats);
    
    // 结束遍历
    if (callbackObj.onFinish) {
        try {
            callbackObj.onFinish(totalCount);
        } catch (e) {
            console.error(`onFinish回调失败: ${e.message}`);
        }
    }
    
    if (config.verbose) {
        console.log(`✅ 遍历完成，共处理 ${totalCount} 个View`);
    }
    
    return totalCount;
}

// ============================ dumpViewHierarchy改进版 ============================

/**
 * dump View层级结构（使用eachAllView实现）
 */
function dumpViewHierarchy(tag, rootView, options = {}) {
    const defaultOptions = {
        showProperties: true,
        maxDepth: 20,
        verbose: true
    };
    const config = { ...defaultOptions, ...options };
    
    console.log('\n' + '='.repeat(80));
    console.log(`📱 VIEW HIERARCHY DUMP [${tag}]`);
    console.log(`🕒 ${new Date().toLocaleString()}`);
    console.log('='.repeat(80));
    
    if (!rootView) {
        console.error('❌ 根View为空！');
        return 0;
    }
    
    // 创建专门用于dump的回调对象
    const dumpCallback = new ViewCallback();
    
    dumpCallback.onStart = function(rootView) {
        console.log(`\n🌳 根View信息:`);
        console.log(`   类名: ${rootView.$className}`);
        console.log(`   哈希: ${rootView.hashCode()}`);
        
        try {
            const Context = Java.use('android.content.Context');
            const Activity = Java.use('android.app.Activity');
            const context = Java.cast(rootView.getContext(), Context);
            const activity = Java.cast(context, Activity);
            console.log(`   所属Activity: ${activity.$className}`);
        } catch (e) {
            // 忽略错误
        }
        
        console.log('\n📋 View层级结构:');
        console.log('='.repeat(60));
    };
    
    dumpCallback.onMatch = function(view, depth, path) {
        if (config.maxDepth && depth > config.maxDepth) {
            return; // 超过最大深度，跳过
        }
        
        const indent = '  '.repeat(depth);
        const className = getSimpleClassName(view);
        const viewId = getViewId(view);
        
        // 构建显示内容
        let displayText = `${indent}├── ${className}`;
        
        if (config.showProperties) {
            displayText += ` [${viewId}]`;
            
            try {
                const visibility = ['VISIBLE', 'INVISIBLE', 'GONE'][view.getVisibility()];
                displayText += ` [${visibility}]`;
            } catch (e) {
                // 忽略
            }
            
            try {
                const enabled = view.isEnabled() ? 'enabled' : 'disabled';
                displayText += ` [${enabled}]`;
            } catch (e) {
                // 忽略
            }
        }
        
        console.log(displayText);
        
        if (config.verbose && depth === 0) {
            console.log(`${indent}│   └── 路径: ${path}`);
        }
    };
    
    dumpCallback.onFinish = function(totalCount) {
        console.log('='.repeat(60));
        console.log(`✅ View层级遍历完成，共 ${totalCount} 个View`);
        console.log('='.repeat(80) + '\n');
    };
    
    return eachAllView(rootView, dumpCallback, config);
}

// ============================ 实用功能函数 ============================

/**
 * 查找特定条件的View
 * @param {object} rootView - 根View
 * @param {Function} predicate - 判断函数，返回true表示匹配
 * @returns {Array} 匹配的View数组
 */
function findViews(rootView, predicate) {
    const results = [];
    
    const findCallback = new ViewCallback();
    findCallback.onMatch = function(view, depth, path) {
        try {
            if (predicate(view, depth, path)) {
                results.push({
                    view: view,
                    depth: depth,
                    path: path,
                    className: view.$className,
                    id: getViewId(view)
                });
            }
        } catch (e) {
            console.error(`判断函数执行失败: ${e.message}`);
        }
    };
    
    eachAllView(rootView, findCallback, { verbose: false });
    return results;
}

/**
 * 按类名查找View
 */
function findViewsByClassName(rootView, className) {
    return findViews(rootView, (view) => {
        return view.$className === className || 
               getSimpleClassName(view) === className;
    });
}

/**
 * 按ID查找View
 */
function findViewsById(rootView, idPattern) {
    return findViews(rootView, (view) => {
        const viewId = getViewId(view);
        return viewId.includes(idPattern);
    });
}

/**
 * 查找特定文本的TextView
 */
function findTextViewsWithText(rootView, text) {
    return findViews(rootView, (view) => {
        if (view.$className.includes('TextView')) {
            try {
                const TextView = Java.use('android.widget.TextView');
                const textView = Java.cast(view, TextView);
                const viewText = textView.getText().toString();
                return viewText.includes(text);
            } catch (e) {
                return false;
            }
        }
        return false;
    });
}

/**
 * 统计各类View的数量
 */
function countViewTypes(rootView) {
    const counts = {};
    
    const countCallback = new ViewCallback();
    countCallback.onMatch = function(view) {
        const className = getSimpleClassName(view);
        counts[className] = (counts[className] || 0) + 1;
    };
    
    eachAllView(rootView, countCallback, { verbose: false });
    
    return Object.entries(counts)
        .sort((a, b) => b[1] - a[1])
        .reduce((obj, [key, value]) => {
            obj[key] = value;
            return obj;
        }, {});
}

/**
 * 批量执行操作
 * @param {object} rootView - 根View
 * @param {Function} action - 要对每个View执行的操作
 */
function batchProcessViews(rootView, action) {
    const results = [];
    
    const processCallback = new ViewCallback();
    processCallback.onMatch = function(view, depth, path) {
        try {
            const result = action(view, depth, path);
            if (result !== undefined) {
                results.push({
                    view: view,
                    depth: depth,
                    path: path,
                    result: result
                });
            }
        } catch (e) {
            console.error(`操作执行失败: ${e.message}`);
        }
    };
    
    eachAllView(rootView, processCallback, { verbose: false });
    return results;
}

// ============================ 快速使用函数 ============================

/**
 * 快速dump当前Activity
 */
function quickDump(activityName, options = {}) {
    Java.perform(function() {
        try {
            const ActivityThread = Java.use('android.app.ActivityThread');
            const activityThread = ActivityThread.currentActivityThread();
            const activities = activityThread.getActivities();
            
            const iterator = activities.values().iterator();
            while (iterator.hasNext()) {
                const activityRecord = iterator.next();
                const activity = activityRecord.get();
                
                if (!activityName || activity.$className.includes(activityName)) {
                    const decorView = activity.getWindow().getDecorView();
                    dumpViewHierarchy(activity.$className, decorView, options);
                    return;
                }
            }
            
            console.warn(`未找到Activity: ${activityName || '任意'}`);
        } catch (e) {
            console.error(`快速dump失败: ${e.message}`);
        }
    });
}

/**
 * 快速查找特定View
 */
function quickFind(activityName, findFunction) {
    Java.perform(function() {
        try {
            const ActivityThread = Java.use('android.app.ActivityThread');
            const activityThread = ActivityThread.currentActivityThread();
            const activities = activityThread.getActivities();
            
            const iterator = activities.values().iterator();
            while (iterator.hasNext()) {
                const activityRecord = iterator.next();
                const activity = activityRecord.get();
                
                if (!activityName || activity.$className.includes(activityName)) {
                    const decorView = activity.getWindow().getDecorView();
                    
                    if (typeof findFunction === 'string') {
                        // 按类名查找
                        const results = findViewsByClassName(decorView, findFunction);
                        console.log(`找到 ${results.length} 个匹配的View:`);
                        results.forEach((result, index) => {
                            console.log(`${index + 1}. ${result.className} [${result.id}] (深度: ${result.depth})`);
                        });
                    } else if (typeof findFunction === 'function') {
                        // 使用自定义函数查找
                        const results = findViews(decorView, findFunction);
                        console.log(`找到 ${results.length} 个匹配的View:`);
                        results.forEach((result, index) => {
                            console.log(`${index + 1}. ${result.className} [${result.id}] (深度: ${result.depth})`);
                        });
                    }
                    
                    return;
                }
            }
            
            console.warn(`未找到Activity: ${activityName || '任意'}`);
        } catch (e) {
            console.error(`快速查找失败: ${e.message}`);
        }
    });
}

// ============================ 导出函数 ============================

module.exports = {
    // 核心遍历函数
    eachAllView,
    ViewCallback,
    SimplePrintCallback,
    
    // dump函数
    dumpViewHierarchy,
    quickDump,
    
    // 查找函数
    findViews,
    findViewsByClassName,
    findViewsById,
    findTextViewsWithText,
    quickFind,
    
    // 统计函数
    countViewTypes,
    
    // 批量处理
    batchProcessViews,
    
    // 工具函数
    getSimpleClassName,
    getViewId,
    isViewGroup,
    generateViewPath
};

// ============================ 使用示例 ============================

/**
 * 示例1：基本遍历
 */
function exampleBasicTraversal() {
    Java.perform(function() {
        const activity = Java.use('com.example.MainActivity').$new();
        const decorView = activity.getWindow().getDecorView();
        
        // 方式1：使用回调对象
        const callback = new SimplePrintCallback();
        eachAllView(decorView, callback);
        
        // 方式2：使用函数回调
        eachAllView(decorView, function(view, depth, path) {
            console.log(`${'  '.repeat(depth)}${getSimpleClassName(view)}`);
        });
    });
}

/**
 * 示例2：查找特定View
 */
function exampleFindViews() {
    Java.perform(function() {
        const activity = Java.use('com.example.MainActivity').$new();
        const decorView = activity.getWindow().getDecorView();
        
        // 查找所有Button
        const buttons = findViewsByClassName(decorView, 'Button');
        console.log(`找到 ${buttons.length} 个Button`);
        
        // 查找特定ID的View
        const specificViews = findViewsById(decorView, 'btn_submit');
        
        // 自定义条件查找
        const customViews = findViews(decorView, (view) => {
            return view.isClickable() && view.isEnabled();
        });
    });
}

/**
 * 示例3：批量操作
 */
function exampleBatchOperations() {
    Java.perform(function() {
        const activity = Java.use('com.example.MainActivity').$new();
        const decorView = activity.getWindow().getDecorView();
        
        // 禁用所有Button
        batchProcessViews(decorView, (view) => {
            if (view.$className.includes('Button')) {
                view.setEnabled(false);
                return 'disabled';
            }
        });
        
        // 统计View类型
        const typeCounts = countViewTypes(decorView);
        console.log('View类型统计:', typeCounts);
    });
}

/**
 * 示例4：快速使用
 */
function exampleQuickUsage() {
    // dump当前Activity
    quickDump('MainActivity');
    
    // 查找所有EditText
    quickFind('LoginActivity', 'EditText');
    
    // 自定义查找条件
    quickFind(null, (view) => {
        return view.isClickable() && view.getVisibility() === 0;
    });
}

// 自动加载提示
setTimeout(function() {
    console.log('🚀 Android UI分析工具集已加载');
    console.log('📖 可用命令:');
    console.log('   - eachAllView(rootView, callback)');
    console.log('   - dumpViewHierarchy("标签", rootView)');
    console.log('   - quickDump("Activity名称")');
    console.log('   - findViewsByClassName(rootView, "Button")');
    console.log('   - quickFind("ActivityName", "ViewType")');
}, 1000);