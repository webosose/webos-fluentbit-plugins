/* @@@LICENSE
 *
 * Copyright (c) 2019 LG Electronics, Inc.
 *
 * Confidential computer software. Valid license from LG required for
 * possession, use or copying. Consistent with FAR 12.211 and 12.212,
 * Commercial Computer Software, Computer Software Documentation, and
 * Technical Data for Commercial Items are licensed to the U.S. Government
 * under vendor's standard commercial license.
 *
 * LICENSE@@@
 */

#include "util/JValueUtil.h"

bool JValueUtil::convertValue(const JValue& json, JValue& value)
{
    value = json;
    return true;
}

bool JValueUtil::convertValue(const JValue& json, string& value)
{
    if (!json.isString())
        return false;
    if (json.asString(value) != CONV_OK) {
        value = "";
        return false;
    }
    return true;
}

bool JValueUtil::convertValue(const JValue& json, int& value)
{
    if (!json.isNumber())
        return false;
    if (json.asNumber<int>(value) != CONV_OK) {
        value = 0;
        return false;
    }
    return true;
}

bool JValueUtil::convertValue(const JValue& json, bool& value)
{
    if (!json.isBoolean())
        return false;
    if (json.asBool(value) != CONV_OK) {
        value = false;
        return false;
    }
    return true;
}
