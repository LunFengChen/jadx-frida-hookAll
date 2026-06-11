function showNativeStacks(thiz) {
  Thread.backtrace(thiz, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n");
}

