/*
 * Copyright 2015 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "MapVir"

#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <cutils/atomic.h>
#include <cutils/log.h>
#include "sprd_map.h"
#include "MapUser.h"

int open_dev(const char *device) {
    int open_flags = O_RDWR;
    int fd = open(device, open_flags);
    if (fd >= 0){
        return fd;
    } else {
        ALOGE("%s, open ion fail, %d(%s)", __func__, -errno, strerror(errno));
        return -errno;
    }
}

void* map_user(int fd, unsigned long phy_addr, size_t size) {
    struct pmem_info data;
    data.phy_addr = phy_addr;
    data.size = size;
    void *base = NULL;
    if (ioctl(fd, MAP_USER_VIR, &data)<0) {
        ALOGE("%s: MAP_USER_VIR  error: %d (%s)", __func__, -errno, strerror(errno));
        close(fd);
        return NULL;
    }else{
        base = (uint8_t *)mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        return base;
    }
}

void unmap_user(int fd, void* mBase, size_t size) {
    if (fd >= 0)
        munmap(mBase, size);
    else
        ALOGE("unmap fail err fd=%d ", fd);
}

void close_dev(int fd) {
    if (fd >= 0)
        close(fd);
}
