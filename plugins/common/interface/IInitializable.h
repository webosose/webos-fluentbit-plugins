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

#ifndef INTERFACE_IINITIALIZABLE_H_
#define INTERFACE_IINITIALIZABLE_H_

#include <glib.h>

#include <iostream>

#include "IClassName.h"
#include "util/Logger.h"

using namespace std;

class IInitializable : public IClassName {
public:
    virtual ~IInitializable(){}

    virtual bool initialize(GMainLoop *mainloop) final
    {
        PLUGIN_INFO("[%s] Start initialization", m_className.c_str());
        m_mainloop = mainloop;
        m_isInitalized = onInitialization();
        PLUGIN_INFO("[%s] End initialization", m_className.c_str());
        return m_isInitalized;
    }

    virtual bool finalize() final
    {
        PLUGIN_INFO("[%s] Start finalization", m_className.c_str());
        m_isFinalized = onFinalization();
        PLUGIN_INFO("[%s] End finalization", m_className.c_str());
        return m_isFinalized;
    }

    virtual bool isInitalized() const { return m_isInitalized; }
    virtual bool isFinalized() const { return m_isFinalized; }

    virtual bool onInitialization() = 0;
    virtual bool onFinalization() = 0;

protected:
    IInitializable()
        : m_mainloop(nullptr),
          m_isInitalized(false),
          m_isFinalized(false)
    {
    }

    GMainLoop *m_mainloop;

private:
    bool m_isInitalized;
    bool m_isFinalized;

};

#endif /* INTERFACE_IINITIALIZABLE_H_ */
