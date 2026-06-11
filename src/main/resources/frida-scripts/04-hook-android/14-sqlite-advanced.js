/**
 * SQLite 高级监控脚本
 * 支持：查询结果读取、事务监控、Native层Hook
 */

// ============ Hook Cursor 读取查询结果 ============

function hookCursor() {
    var Cursor = Java.use("android.database.Cursor");
    
    // Hook getString
    Cursor.getString.implementation = function(columnIndex) {
        var result = this.getString(columnIndex);
        var columnName = this.getColumnName(columnIndex);
        console.log("[Cursor] getString - 列: " + columnName + " = " + result);
        return result;
    };
    
    // Hook getInt
    Cursor.getInt.implementation = function(columnIndex) {
        var result = this.getInt(columnIndex);
        var columnName = this.getColumnName(columnIndex);
        console.log("[Cursor] getInt - 列: " + columnName + " = " + result);
        return result;
    };
    
    // Hook getLong
    Cursor.getLong.implementation = function(columnIndex) {
        var result = this.getLong(columnIndex);
        var columnName = this.getColumnName(columnIndex);
        console.log("[Cursor] getLong - 列: " + columnName + " = " + result);
        return result;
    };
    
    // Hook getBlob
    Cursor.getBlob.implementation = function(columnIndex) {
        var result = this.getBlob(columnIndex);
        var columnName = this.getColumnName(columnIndex);
        console.log("[Cursor] getBlob - 列: " + columnName + ", 长度: " + (result ? result.length : 0));
        return result;
    };
    
    console.log("[+] Cursor Hook 完成");
}

// ============ Hook 事务操作 ============

function hookTransaction() {
    var SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");
    
    // Hook beginTransaction
    SQLiteDatabase.beginTransaction.implementation = function() {
        console.log("\n[SQLite] 开始事务");
        console.log("  数据库: " + this.getPath());
        return this.beginTransaction();
    };
    
    // Hook setTransactionSuccessful
    SQLiteDatabase.setTransactionSuccessful.implementation = function() {
        console.log("\n[SQLite] 标记事务成功");
        console.log("  数据库: " + this.getPath());
        return this.setTransactionSuccessful();
    };
    
    // Hook endTransaction
    SQLiteDatabase.endTransaction.implementation = function() {
        console.log("\n[SQLite] 结束事务");
        console.log("  数据库: " + this.getPath());
        return this.endTransaction();
    };
    
    console.log("[+] Transaction Hook 完成");
}

// ============ Hook Native 层 SQLite ============

function hookNativeSQLite() {
    // Hook sqlite3_open
    var sqlite3_open = Module.findExportByName("libsqlite.so", "sqlite3_open");
    if (sqlite3_open) {
        Interceptor.attach(sqlite3_open, {
            onEnter: function(args) {
                this.filename = Memory.readUtf8String(args[0]);
            },
            onLeave: function(retval) {
                console.log("\n[Native SQLite] sqlite3_open");
                console.log("  文件: " + this.filename);
                console.log("  返回值: " + retval);
            }
        });
        console.log("[+] sqlite3_open Hook 完成");
    }
    
    // Hook sqlite3_exec
    var sqlite3_exec = Module.findExportByName("libsqlite.so", "sqlite3_exec");
    if (sqlite3_exec) {
        Interceptor.attach(sqlite3_exec, {
            onEnter: function(args) {
                this.sql = Memory.readUtf8String(args[1]);
            },
            onLeave: function(retval) {
                console.log("\n[Native SQLite] sqlite3_exec");
                console.log("  SQL: " + this.sql);
                console.log("  返回值: " + retval);
            }
        });
        console.log("[+] sqlite3_exec Hook 完成");
    }
    
    // Hook sqlite3_prepare_v2
    var sqlite3_prepare_v2 = Module.findExportByName("libsqlite.so", "sqlite3_prepare_v2");
    if (sqlite3_prepare_v2) {
        Interceptor.attach(sqlite3_prepare_v2, {
            onEnter: function(args) {
                this.sql = Memory.readUtf8String(args[1]);
            },
            onLeave: function(retval) {
                console.log("\n[Native SQLite] sqlite3_prepare_v2");
                console.log("  SQL: " + this.sql);
                console.log("  返回值: " + retval);
            }
        });
        console.log("[+] sqlite3_prepare_v2 Hook 完成");
    }
}

// ============ 导出数据库内容 ============

function dumpDatabase(dbPath, tableName) {
    Java.perform(function() {
        var SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");
        var db = SQLiteDatabase.openDatabase(dbPath, null, 0);
        
        console.log("\n========== 导出表: " + tableName + " ==========");
        
        var cursor = db.rawQuery("SELECT * FROM " + tableName, null);
        var columnCount = cursor.getColumnCount();
        
        // 打印列名
        var columns = [];
        for (var i = 0; i < columnCount; i++) {
            columns.push(cursor.getColumnName(i));
        }
        console.log("列名: " + columns.join(" | "));
        console.log("----------------------------------------");
        
        // 打印数据
        var rowCount = 0;
        while (cursor.moveToNext()) {
            var row = [];
            for (var i = 0; i < columnCount; i++) {
                var type = cursor.getType(i);
                var value;
                switch (type) {
                    case 0: // NULL
                        value = "NULL";
                        break;
                    case 1: // INTEGER
                        value = cursor.getLong(i);
                        break;
                    case 2: // FLOAT
                        value = cursor.getDouble(i);
                        break;
                    case 3: // STRING
                        value = cursor.getString(i);
                        break;
                    case 4: // BLOB
                        value = "[BLOB:" + cursor.getBlob(i).length + "字节]";
                        break;
                    default:
                        value = "UNKNOWN";
                }
                row.push(value);
            }
            console.log(row.join(" | "));
            rowCount++;
        }
        
        console.log("----------------------------------------");
        console.log("总行数: " + rowCount);
        
        cursor.close();
        db.close();
    });
}

// ============ 列出所有表 ============

function listTables(dbPath) {
    Java.perform(function() {
        var SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");
        var db = SQLiteDatabase.openDatabase(dbPath, null, 0);
        
        console.log("\n========== 数据库表列表 ==========");
        console.log("数据库: " + dbPath);
        
        var cursor = db.rawQuery(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name", 
            null
        );
        
        var tables = [];
        while (cursor.moveToNext()) {
            var tableName = cursor.getString(0);
            tables.push(tableName);
            console.log("  - " + tableName);
        }
        
        cursor.close();
        db.close();
        
        console.log("总计: " + tables.length + " 个表");
        return tables;
    });
}

// ============ 主函数 ============

function main() {
    Java.perform(function() {
        console.log("\n========== SQLite 高级监控开始 ==========");
        
        hookCursor();
        hookTransaction();
        hookNativeSQLite();
        
        console.log("========================================\n");
    });
}

// 启动监控
setImmediate(main);

// ============ RPC 导出函数 ============

rpc.exports = {
    listTables: listTables,
    dumpDatabase: dumpDatabase
};
