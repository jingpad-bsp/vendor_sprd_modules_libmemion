LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
    MapUser.c \

LOCAL_C_INCLUDES:= \
    vendor/sprd/external/kernel-headers

LOCAL_SHARED_LIBRARIES :=       \
        libutils                \
        libcutils               \
        liblog

LOCAL_MODULE := libmapuser
LOCAL_MODULE_TAGS := optional

LOCAL_PROPRIETARY_MODULE := true
include $(BUILD_SHARED_LIBRARY)

