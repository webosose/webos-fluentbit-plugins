/* @@@LICENSE
 *
 * Copyright (c) 2021 LG Electronics, Inc.
 *
 * Confidential computer software. Valid license from LG required for
 * possession, use or copying. Consistent with FAR 12.211 and 12.212,
 * Commercial Computer Software, Computer Software Documentation, and
 * Technical Data for Commercial Items are licensed to the U.S. Government
 * under vendor's standard commercial license.
 *
 * LICENSE@@@
 */

#ifndef _PLUGIN_LOG_H
#define _PLUGIN_LOG_H

#include <stdio.h>

#define PLUGIN_DEBUG(fmt, ...) \
    printf("[debug][%s] " fmt " \n", __FUNCTION__ , ##__VA_ARGS__)

#define PLUGIN_INFO(fmt, ...) \
    printf("[ info][%s] " fmt " \n", __FUNCTION__ , ##__VA_ARGS__)

#define PLUGIN_ERROR(fmt, ...) \
    printf("[error][%s] " fmt " \n", __FUNCTION__ , ##__VA_ARGS__)

#endif /* PLUGIN_LOG_H */