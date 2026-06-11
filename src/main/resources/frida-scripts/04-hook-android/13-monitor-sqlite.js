/**
 * SQLite 数据库监控脚本（包含微信数据库解密）
 * 功能：监控数据库操作、获取加密密钥、Hook MD5算法
 */

// ============ 辅助函数 ============
function toHex(data) {
    var ByteString = Java.use("com.android.okhttp.okio.ByteString");
    return ByteString.of(data).hex();
}

function toBase64(data) {
    var ByteString = Java.use("com.android.okhttp.okio.ByteString");
    return ByteString.of(data).base64();
}

function toUtf8(data) {
    var ByteString = Java.use("com.android.okhttp.okio.ByteString");
    return ByteString.of(data).utf8();
}

// ============ Hook MD5 算法 ============
function hookMD5() {
    var MessageDigest = Java.use("java.security.MessageDigest");
    
    MessageDigest.digest.overload().implementation = function () {
        console.log("[MD5] digest() 被调用");
        var result = this.digest();
        var algorithm = this.getAlgorithm();
        
        if (algorithm === "MD5") {
            console.log("[MD5] 输出(Hex): " + toHex(result));
            console.log("[MD5] 输出(Base64): " + toBase64(result));
        }
        return result;
    };
    
    MessageDigest.digest.overload('[B').implementation = function (data) {
        console.log("[MD5] digest([B]) 被调用");
        var algorithm = this.getAlgorithm();
        
        if (algorithm === "MD5") {
            console.log("[MD5] 输入(Hex): " + toHex(data));
            console.log("[MD5] 输入(Utf8): " + toUtf8(data));
        }
        
        var result = this.digest(data);
        
        if (algorithm === "MD5") {
            console.log("[MD5] 输出(Hex): " + toHex(result));
            console.log("[MD5] 输出(Base64): " + toBase64(result));
        }
        return result;
    };
    
    console.log("[+] MD5 Hook 完成");
}

// ============ Hook SQLCipher ============
function hookSQLCipher() {
    try {
        var SQLiteDatabase = Java.use("net.sqlcipher.database.SQLiteDatabase");
        
        SQLiteDatabase.openDatabase.overload(
            "java.lang.String",
            "java.lang.String",
            "net.sqlcipher.database.SQLiteDatabase$CursorFactory",
            "int"
        ).implementation = function(path, password, factory, flags) {
            console.log("\n[SQLCipher] openDatabase");
            console.log("  路径: " + path);
            console.log("  密码: " + password);
            return this.openDatabase(path, password, factory, flags);
        };
        
        console.log("[+] SQLCipher Hook 完成");
    } catch (e) {
        console.log("[-] SQLCipher 未找到");
    }
}

// ============ Hook 微信 WCDB ============
function hookWeChatWCDB() {
    try {
        var SQLiteDatabase = Java.use("com.tencent.wcdb.database.SQLiteDatabase");
        
        SQLiteDatabase.openDatabase.overload(
            "java.lang.String",
            "[B",
            "com.tencent.wcdb.database.SQLiteDatabase$CursorFactory",
            "int",
            "com.tencent.wcdb.DatabaseErrorHandler"
        ).implementation = function(path, password, factory, flags, errorHandler) {
            console.log("\n[WCDB] openDatabase");
            console.log("  路径: " + path);
            
            if (password) {
                var passwordStr = "";
                for (var i = 0; i < password.length; i++) {
                    passwordStr += ("0" + (password[i] & 0xFF).toString(16)).slice(-2);
                }
                console.log("  密码(HEX): " + passwordStr);
                console.log("  密码长度: " + password.length + " 字节");
            }
            
            return this.openDatabase(path, password, factory, flags, errorHandler);
        };
        
        console.log("[+] WCDB Hook 完成");
    } catch (e) {
        console.log("[-] WCDB 未找到");
    }
}

// ============ Hook Native 层 sqlite3_key ============
function hookNativeSQLite() {
    var sqlite3_key = Module.findExportByName("libwcdb.so", "sqlite3_key");
    if (!sqlite3_key) {
        sqlite3_key = Module.findExportByName("libsqlcipher.so", "sqlite3_key");
    }
    
    if (sqlite3_key) {
        Interceptor.attach(sqlite3_key, {
            onEnter: function(args) {
                var keyLength = args[2].toInt32();
                if (keyLength > 0) {
                    var keyBytes = Memory.readByteArray(args[1], keyLength);
                    var keyHex = "";
                    var keyArray = new Uint8Array(keyBytes);
                    for (var i = 0; i < keyArray.length; i++) {
                        keyHex += ("0" + keyArray[i].toString(16)).slice(-2);
                    }
                    
                    console.log("\n[Native] sqlite3_key");
                    console.log("  密钥(HEX): " + keyHex);
                    console.log("  密钥长度: " + keyLength);
                }
            }
        });
        console.log("[+] sqlite3_key Hook 完成");
    }
}

// ============ Hook SQLiteDatabase ============
function hookSQLiteDatabase() {
    var SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");
    
    // Hook 数据库打开
    SQLiteDatabase.openDatabase.overload(
        "java.lang.String", 
        "android.database.sqlite.SQLiteDatabase$CursorFactory", 
        "int"
    ).implementation = function(path, factory, flags) {
        console.log("\n[SQLite] 打开数据库");
        console.log("  路径: " + path);
        return this.openDatabase(path, factory, flags);
    };
    
    // Hook execSQL
    SQLiteDatabase.execSQL.overload("java.lang.String").implementation = function(sql) {
        console.log("\n[SQLite] execSQL: " + sql);
        return this.execSQL(sql);
    };
    
    // Hook rawQuery
    SQLiteDatabase.rawQuery.overload("java.lang.String", "[Ljava.lang.String;").implementation = function(sql, args) {
        console.log("\n[SQLite] rawQuery: " + sql);
        return this.rawQuery(sql, args);
    };
    
    console.log("[+] SQLiteDatabase Hook 完成");
}

// ============ 主函数 ============
function main() {
    Java.perform(function() {
        console.log("\n========== SQLite 监控开始 ==========");
        
        hookMD5();
        hookSQLCipher();
        hookWeChatWCDB();
        hookNativeSQLite();
        hookSQLiteDatabase();
        
        console.log("========================================\n");
    });
}

setImmediate(main);
