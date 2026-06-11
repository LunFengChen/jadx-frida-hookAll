/**
 * 打印某个对象的所有字段
 * @param obj 要打印的对象
 */
function showAllFields(obj){
  console.error("\nshowAllFields=================>"+obj);
  let javaCls = Java.use("java.lang.Class");
  let currentCls = javaCls.forName(obj.$className);
  let fields = currentCls.getDeclaredFields();
  fields.forEach(function (field) {
    console.log("field => " + field);
    let AcccessibleCls = Java.use("java.lang.reflect.AccessibleObject");
    let AcccessibleObj = Java.cast(field, AcccessibleCls);
    AcccessibleObj.setAccessible(true);
    console.log("fieldValue => " + field.get(obj));
  });
  console.log("showAllFields=================<\n");
}

/**
 * 获取对象的某个字段名称
 * @param obj 要获取的对象
 * @param fieldName   字段名称
 * @returns 返回字段值
 */
function getFieldValue(obj, fieldName){
  let javaCls = Java.use("java.lang.Class");
  let currentCls = javaCls.forName(obj.$className);
  let field = currentCls.getDeclaredField(fieldName);
  let AcccessibleCls = Java.use("java.lang.reflect.AccessibleObject");
  let AcccessibleObj = Java.cast(field, AcccessibleCls);
  AcccessibleObj.setAccessible(true);
  return field.get(obj);
}
