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

#ifndef INTERFACE_ICLASSNAME_H_
#define INTERFACE_ICLASSNAME_H_

#include <string>

using namespace std;

class IClassName {
public:
    IClassName() : m_className("Unknown"){}
    virtual ~IClassName(){}

    const string& getClassName() const { return m_className; }

    void setClassName(const string& className) { m_className = className; }

protected:
    string m_className;
};

#endif /* INTERFACE_ICLASSNAME_H_ */
