#pragma once

#include <android/log.h>

#define LOG_TAG "AndTunnel"

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

#define UDP_LOGI(...)  LOGI(__VA_ARGS__)
#define UDP_LOGE(...)  LOGE(__VA_ARGS__)

#define TCP_LOGI(...)  LOGI(__VA_ARGS__)
#define TCP_LOGE(...)  LOGE(__VA_ARGS__)
#define TCP_DEBUG(...) LOGE(__VA_ARGS__)