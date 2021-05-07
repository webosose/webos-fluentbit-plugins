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

#ifndef INTERFACE_ITIMESTAMP_H_
#define INTERFACE_ITIMESTAMP_H_

#include <iostream>

#include "util/Time.h"

using namespace std;

class ITimestamp {
public:
    ITimestamp()
        : m_startTime(""),
          m_endTime("")
    {

    }

    virtual ~ITimestamp()
    {

    }

    void start()
    {
        m_startTime = Time::getCurrentTime();
    }

    void end()
    {
        m_endTime = Time::getCurrentTime();
    }

    const string& getStartTime()
    {
        return m_startTime;
    }

    const string& getEndTime()
    {
        return m_endTime;
    }

protected:
    string m_startTime;
    string m_endTime;
};

#endif /* INTERFACE_ITIMESTAMP_H_ */
