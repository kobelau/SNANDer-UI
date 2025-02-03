// flashcmd_api.c
/*
 * Copyright (C) 2018-2021 McMCC <mcmcc@mail.ru>
 * flashcmd_api.c
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <stdio.h>
#include "flashcmd_api.h"
#include <time.h>

#ifdef EEPROM_SUPPORT
#define __EEPROM___	"or EEPROM"
extern int eepromsize;
extern int mw_eepromsize;
extern int seepromsize;
#else
#define __EEPROM___	""
#endif

// 定义内部函数，带有进度回调
static int snor_read_with_progress(unsigned char *buf, unsigned long from, unsigned long len, progress_callback_t progress_callback) {
    int ret = 0;
    int chunk_size = 1572864; // 每次读取8MB
    unsigned long progress_step = len / 100; // 1%的字节数
    unsigned long last_progress = 0; // 记录上次调用回调的进度
    clock_t last_callback_time = clock(); // 上次调用回调的时间
    double elapsed_seconds = 0.0;

    for (unsigned long i = 0; i < len; i += chunk_size) {
        unsigned long current_chunk_size = (i + chunk_size > len) ? (len - i) : chunk_size;
        // 读取数据的逻辑
        ret = snor_read(buf + i, from + i, current_chunk_size);
        if (ret < 0) break;

        // 计算自上次回调后的时间差
        elapsed_seconds = (clock() - last_callback_time) / (double)CLOCKS_PER_SEC;

        // 每1秒或1%更新一次进度
        if (progress_callback && (elapsed_seconds >= 1.0 || i >= last_progress + progress_step)) {
            last_progress = i; // 更新上次记录的进度
            last_callback_time = clock(); // 更新上次调用时间
            progress_callback(i + current_chunk_size, len);
        }
    }

    // 确保最后一次进度更新到100%
    if (progress_callback && last_progress < len) {
        progress_callback(len, len);
    }

    return ret;
}

static int snor_write_with_progress(unsigned char *buf, unsigned long to, unsigned long len, progress_callback_t progress_callback) {
    int ret = 0;
    int chunk_size = 1572864; // 每次写入8MB
    unsigned long progress_step = len / 100; // 1%的字节数
    unsigned long last_progress = 0; // 记录上次调用回调的进度
    clock_t last_callback_time = clock(); // 上次调用回调的时间
    double elapsed_seconds = 0.0;

    for (unsigned long i = 0; i < len; i += chunk_size) {
        unsigned long current_chunk_size = (i + chunk_size > len) ? (len - i) : chunk_size;
        // 写入数据的逻辑
        ret = snor_write(buf + i, to + i, current_chunk_size);
        if (ret < 0) break;

        // 计算自上次回调后的时间差
        elapsed_seconds = (clock() - last_callback_time) / (double)CLOCKS_PER_SEC;

        // 每1秒或1%更新一次进度
        if (progress_callback && (elapsed_seconds >= 1.0 || i >= last_progress + progress_step)) {
            last_progress = i; // 更新上次记录的进度
            last_callback_time = clock(); // 更新上次调用时间
            progress_callback(i + current_chunk_size, len);
        }
    }

    // 确保最后一次进度更新到100%
    if (progress_callback && last_progress < len) {
        progress_callback(len, len);
    }

    return ret;
}

static int snor_erase_with_progress(unsigned long offs, unsigned long len, progress_callback_t progress_callback) {
    int ret = 0;
    int chunk_size = 1572864; // 每次擦除8MB
    unsigned long progress_step = len / 100; // 1%的字节数
    unsigned long last_progress = 0; // 记录上次调用回调的进度
    clock_t last_callback_time = clock(); // 上次调用回调的时间
    double elapsed_seconds = 0.0;

    for (unsigned long i = 0; i < len; i += chunk_size) {
        unsigned long current_chunk_size = (i + chunk_size > len) ? (len - i) : chunk_size;
        // 擦除数据的逻辑
        ret = snor_erase(offs + i, current_chunk_size);
        if (ret < 0) break;

        // 计算自上次回调后的时间差
        elapsed_seconds = (clock() - last_callback_time) / (double)CLOCKS_PER_SEC;

        // 每1秒或1%更新一次进度
        if (progress_callback && (elapsed_seconds >= 1.0 || i >= last_progress + progress_step)) {
            last_progress = i; // 更新上次记录的进度
            last_callback_time = clock(); // 更新上次调用时间
            progress_callback(i + current_chunk_size, len);
        }
    }

    // 确保最后一次进度更新到100%
    if (progress_callback && last_progress < len) {
        progress_callback(len, len);
    }

    return ret;
}

static int snand_read_with_progress(unsigned char *buf, unsigned long from, unsigned long len, progress_callback_t progress_callback) {
    int ret = 0;
    int chunk_size = 1572864; // 每次读取8MB
    unsigned long progress_step = len / 100; // 1%的字节数
    unsigned long last_progress = 0; // 记录上次调用回调的进度
    clock_t last_callback_time = clock(); // 上次调用回调的时间
    double elapsed_seconds = 0.0;

    for (unsigned long i = 0; i < len; i += chunk_size) {
        unsigned long current_chunk_size = (i + chunk_size > len) ? (len - i) : chunk_size;
        // 读取数据的逻辑
        ret = snand_read(buf + i, from + i, current_chunk_size);
        if (ret < 0) break;

        // 计算自上次回调后的时间差
        elapsed_seconds = (clock() - last_callback_time) / (double)CLOCKS_PER_SEC;

        // 每1秒或1%更新一次进度
        if (progress_callback && (elapsed_seconds >= 1.0 || i >= last_progress + progress_step)) {
            last_progress = i; // 更新上次记录的进度
            last_callback_time = clock(); // 更新上次调用时间
            progress_callback(i + current_chunk_size, len);
        }
    }

    // 确保最后一次进度更新到100%
    if (progress_callback && last_progress < len) {
        progress_callback(len, len);
    }

    return ret;
}


static int snand_write_with_progress(unsigned char *buf, unsigned long to, unsigned long len, progress_callback_t progress_callback) {
    int ret = 0;
    int chunk_size = 1572864; // 每次写入8MB
    unsigned long progress_step = len / 100; // 1%的字节数
    unsigned long last_progress = 0; // 记录上次调用回调的进度
    clock_t last_callback_time = clock(); // 上次调用回调的时间
    double elapsed_seconds = 0.0;

    for (unsigned long i = 0; i < len; i += chunk_size) {
        unsigned long current_chunk_size = (i + chunk_size > len) ? (len - i) : chunk_size;
        // 写入数据的逻辑
        ret = snand_write(buf + i, to + i, current_chunk_size);
        if (ret < 0) break;

        // 计算自上次回调后的时间差
        elapsed_seconds = (clock() - last_callback_time) / (double)CLOCKS_PER_SEC;

        // 每1秒或1%更新一次进度
        if (progress_callback && (elapsed_seconds >= 1.0 || i >= last_progress + progress_step)) {
            last_progress = i; // 更新上次记录的进度
            last_callback_time = clock(); // 更新上次调用时间
            progress_callback(i + current_chunk_size, len);
        }
    }

    // 确保最后一次进度更新到100%
    if (progress_callback && last_progress < len) {
        progress_callback(len, len);
    }

    return ret;
}

static int snand_erase_with_progress(unsigned long offs, unsigned long len, progress_callback_t progress_callback) {
    int ret = 0;
    int chunk_size = 1572864; // 每次擦除8MB
    unsigned long progress_step = len / 100; // 1%的字节数
    unsigned long last_progress = 0; // 记录上次调用回调的进度
    clock_t last_callback_time = clock(); // 上次调用回调的时间
    double elapsed_seconds = 0.0;

    for (unsigned long i = 0; i < len; i += chunk_size) {
        unsigned long current_chunk_size = (i + chunk_size > len) ? (len - i) : chunk_size;
        // 擦除数据的逻辑
        ret = snand_erase(offs + i, current_chunk_size);
        if (ret < 0) break;

        // 计算自上次回调后的时间差
        elapsed_seconds = (clock() - last_callback_time) / (double)CLOCKS_PER_SEC;

        // 每1秒或1%更新一次进度
        if (progress_callback && (elapsed_seconds >= 1.0 || i >= last_progress + progress_step)) {
            last_progress = i; // 更新上次记录的进度
            last_callback_time = clock(); // 更新上次调用时间
            progress_callback(i + current_chunk_size, len);
        }
    }

    // 确保最后一次进度更新到100%
    if (progress_callback && last_progress < len) {
        progress_callback(len, len);
    }

    return ret;
}

#ifdef EEPROM_SUPPORT
static int i2c_eeprom_read_with_progress(unsigned char *buf, unsigned long from, unsigned long len, progress_callback_t progress_callback) {
    int ret = 0;
    int chunk_size = 4096; // 假设每次读取1024字节
    for (unsigned long i = 0; i < len; i += chunk_size) {
        unsigned long current_chunk_size = (i + chunk_size > len) ? (len - i) : chunk_size;
        // 读取数据的逻辑
        ret = i2c_eeprom_read(buf + i, from + i, current_chunk_size);
        if (ret < 0) break;
        if (progress_callback) {
            progress_callback(i + current_chunk_size, len);
        }
    }
    return ret;
}

static int i2c_eeprom_write_with_progress(unsigned char *buf, unsigned long to, unsigned long len, progress_callback_t progress_callback) {
    int ret = 0;
    int chunk_size = 4096; // 假设每次写入1024字节
    for (unsigned long i = 0; i < len; i += chunk_size) {
        unsigned long current_chunk_size = (i + chunk_size > len) ? (len - i) : chunk_size;
        // 写入数据的逻辑
        ret = i2c_eeprom_write(buf + i, to + i, current_chunk_size);
        if (ret < 0) break;
        if (progress_callback) {
            progress_callback(i + current_chunk_size, len);
        }
    }
    return ret;
}

static int i2c_eeprom_erase_with_progress(unsigned long offs, unsigned long len, progress_callback_t progress_callback) {
    int ret = 0;
    int chunk_size = 4096; // 假设每次擦除1024字节
    for (unsigned long i = 0; i < len; i += chunk_size) {
        unsigned long current_chunk_size = (i + chunk_size > len) ? (len - i) : chunk_size;
        // 擦除数据的逻辑
        ret = i2c_eeprom_erase(offs + i, current_chunk_size);
        if (ret < 0) break;
        if (progress_callback) {
            progress_callback(i + current_chunk_size, len);
        }
    }
    return ret;
}

static int mw_eeprom_read_with_progress(unsigned char *buf, unsigned long from, unsigned long len, progress_callback_t progress_callback) {
    int ret = 0;
    int chunk_size = 4096; // 假设每次读取1024字节
    for (unsigned long i = 0; i < len; i += chunk_size) {
        unsigned long current_chunk_size = (i + chunk_size > len) ? (len - i) : chunk_size;
        // 读取数据的逻辑
        ret = mw_eeprom_read(buf + i, from + i, current_chunk_size);
        if (ret < 0) break;
        if (progress_callback) {
            progress_callback(i + current_chunk_size, len);
        }
    }
    return ret;
}

static int mw_eeprom_write_with_progress(unsigned char *buf, unsigned long to, unsigned long len, progress_callback_t progress_callback) {
    int ret = 0;
    int chunk_size = 4096; // 假设每次写入1024字节
    for (unsigned long i = 0; i < len; i += chunk_size) {
        unsigned long current_chunk_size = (i + chunk_size > len) ? (len - i) : chunk_size;
        // 写入数据的逻辑
        ret = mw_eeprom_write(buf + i, to + i, current_chunk_size);
        if (ret < 0) break;
        if (progress_callback) {
            progress_callback(i + current_chunk_size, len);
        }
    }
    return ret;
}

static int mw_eeprom_erase_with_progress(unsigned long offs, unsigned long len, progress_callback_t progress_callback) {
    int ret = 0;
    int chunk_size = 4096; // 假设每次擦除1024字节
    for (unsigned long i = 0; i < len; i += chunk_size) {
        unsigned long current_chunk_size = (i + chunk_size > len) ? (len - i) : chunk_size;
        // 擦除数据的逻辑
        ret = mw_eeprom_erase(offs + i, current_chunk_size);
        if (ret < 0) break;
        if (progress_callback) {
            progress_callback(i + current_chunk_size, len);
        }
    }
    return ret;
}

static int spi_eeprom_read_with_progress(unsigned char *buf, unsigned long from, unsigned long len, progress_callback_t progress_callback) {
    int ret = 0;
    int chunk_size = 4096; // 假设每次读取1024字节
    for (unsigned long i = 0; i < len; i += chunk_size) {
        unsigned long current_chunk_size = (i + chunk_size > len) ? (len - i) : chunk_size;
        // 读取数据的逻辑
        ret = spi_eeprom_read(buf + i, from + i, current_chunk_size);
        if (ret < 0) break;
        if (progress_callback) {
            progress_callback(i + current_chunk_size, len);
        }
    }
    return ret;
}

static int spi_eeprom_write_with_progress(unsigned char *buf, unsigned long to, unsigned long len, progress_callback_t progress_callback) {
    int ret = 0;
    int chunk_size = 4096; // 假设每次写入1024字节
    for (unsigned long i = 0; i < len; i += chunk_size) {
        unsigned long current_chunk_size = (i + chunk_size > len) ? (len - i) : chunk_size;
        // 写入数据的逻辑
        ret = spi_eeprom_write(buf + i, to + i, current_chunk_size);
        if (ret < 0) break;
        if (progress_callback) {
            progress_callback(i + current_chunk_size, len);
        }
    }
    return ret;
}

static int spi_eeprom_erase_with_progress(unsigned long offs, unsigned long len, progress_callback_t progress_callback) {
    int ret = 0;
    int chunk_size = 4096; // 假设每次擦除1024字节
    for (unsigned long i = 0; i < len; i += chunk_size) {
        unsigned long current_chunk_size = (i + chunk_size > len) ? (len - i) : chunk_size;
        // 擦除数据的逻辑
        ret = spi_eeprom_erase(offs + i, current_chunk_size);
        if (ret < 0) break;
        if (progress_callback) {
            progress_callback(i + current_chunk_size, len);
        }
    }
    return ret;
}
#endif

long flash_cmd_init(struct flash_cmd *cmd)
{
    long flen = -1;

#ifdef EEPROM_SUPPORT
    if ((eepromsize <= 0) && (mw_eepromsize <= 0) && (seepromsize <= 0)) {
#endif
        if ((flen = snor_init()) > 0) {
            cmd->flash_erase = snor_erase_with_progress;
            cmd->flash_write = snor_write_with_progress;
            cmd->flash_read  = snor_read_with_progress;
        } else if ((flen = snand_init()) > 0) {
            cmd->flash_erase = snand_erase_with_progress;
            cmd->flash_write = snand_write_with_progress;
            cmd->flash_read  = snand_read_with_progress;
        }
#ifdef EEPROM_SUPPORT
    } else if ((eepromsize > 0) || (mw_eepromsize > 0) || (seepromsize > 0)) {
        if ((eepromsize > 0) && (flen = i2c_init()) > 0) {
            cmd->flash_erase = i2c_eeprom_erase_with_progress;
            cmd->flash_write = i2c_eeprom_write_with_progress;
            cmd->flash_read  = i2c_eeprom_read_with_progress;
        } else if ((mw_eepromsize > 0) && (flen = mw_init()) > 0) {
            cmd->flash_erase = mw_eeprom_erase_with_progress;
            cmd->flash_write = mw_eeprom_write_with_progress;
            cmd->flash_read  = mw_eeprom_read_with_progress;
        } else if ((seepromsize > 0) && (flen = spi_eeprom_init()) > 0) {
            cmd->flash_erase = spi_eeprom_erase_with_progress;
            cmd->flash_write = spi_eeprom_write_with_progress;
            cmd->flash_read  = spi_eeprom_read_with_progress;
        }
    }
#endif
    else
        printf("\nFlash" __EEPROM___ " not found!!!!\n\n");

    return flen;
}

void support_flash_list(void)
{
    support_snand_list();
    printf("\n");
    support_snor_list();
#ifdef EEPROM_SUPPORT
    printf("\n");
    support_i2c_eeprom_list();
    printf("\n");
    support_mw_eeprom_list();
    printf("\n");
    support_spi_eeprom_list();
#endif
}
/* End of [flashcmd.c] package */
