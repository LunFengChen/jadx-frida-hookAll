/*
 * 查找地址所在的 SO 模块
 * 用于定位某个地址属于哪个 SO，或者验证地址是否在预期的 SO 中
 */

function whichSo(addrPtr, expectedSoName) {
    console.warn(`[*] address is at: ${addrPtr}`);
    
    var addr = ptr(addrPtr);
    var modules = Process.enumerateModulesSync(); // 已排序，base 由低到高
    
    // 遍历所有模块，查找地址所在的 SO
    for (const m of modules) {
        var start = m.base;
        var end = m.base.add(m.size);
        
        // 检查地址是否在当前模块范围内
        if (addr.compare(start) >= 0 && addr.compare(end) < 0) {
            var offset = addr.sub(start);
            var info = {
                inSo: true,
                soName: m.name,
                offset: "0x" + offset.toString(16),
                expectedSoName: expectedSoName,
                isInExpectedSo: m.name === expectedSoName,
                soPath: m.path,
                base: start,
                end: end,
            };
            
            console.log(JSON.stringify(info, null, 2));
            return info;
        }
    }
    
    // 不在任何 SO 中，查找所在的内存段
    var r = Process.findRangeByAddress(addr);
    var offset = r ? addr.sub(r.base) : ptr(0);
    var info = {
        inSo: false,
        rangeBase: r ? r.base : null,
        rangeSize: r ? r.size : null,
        protection: r ? r.protection : null,
        file: r && r.file ? r.file.path : null,
        offset: "0x" + offset.toString(16),
    };
    
    console.log(JSON.stringify(info, null, 2));
    return info;
}

/*
 * 使用示例：
 * 
 * 1. 查找地址所在的 SO
 *    whichSo("0x7b12345678")
 * 
 * 2. 验证地址是否在指定的 SO 中
 *    whichSo("0x7b12345678", "libnative.so")
 * 
 * 3. 常见使用场景：
 *    - Hook 时获取的地址，想知道是哪个 SO 的
 *    - 分析 native 层调用栈时，定位函数所在模块
 *    - 验证 hook 点是否在预期的库中
 */