# ldkit - LD_PRELOAD 用户态 Rootkit
# 仅供安全研究与教学用途

# Android NDK 路径
NDK_PATH := F:/AAAA/android-ndk-r28
NDK_TOOLCHAIN := $(NDK_PATH)/toolchains/llvm/prebuilt/windows-x86_64/bin

# 目标平台（Android ARM64）
API_LEVEL := 35
CC := $(NDK_TOOLCHAIN)/aarch64-linux-android$(API_LEVEL)-clang

# 编译选项
CFLAGS := -Wall -Wextra -std=c11 -O2 -fPIC
LDFLAGS := -shared -ldl

# 输出
TARGET := libldkit.so
SRC := ldkit.c

.PHONY: all clean push

all: $(TARGET)

$(TARGET): $(SRC) config.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(TARGET) $(SRC)

# 推送到 Android 设备
push: $(TARGET)
	adb push $(TARGET) /data/local/tmp/
	adb shell chmod 755 /data/local/tmp/$(TARGET)

clean:
	rm -f $(TARGET)
