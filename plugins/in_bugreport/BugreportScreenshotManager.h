// Copyright (c) 2021 LG Electronics, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

#ifndef BUGREPORTSCREENSHOTMANAGER_H_
#define BUGREPORTSCREENSHOTMANAGER_H_

#include <list>
#include <string>
#include <gio/gio.h>
#include <glib.h>

#include "FluentBit.h"
#include "bus/LunaHandle.h"
#include "interface/IClassName.h"
#include "interface/ISingleton.h"

using namespace std;

class BugreportScreenshotManager : public IClassName {
public:
    BugreportScreenshotManager();
    virtual ~BugreportScreenshotManager();

    bool initialize(LunaHandle* lunaHandle);
    bool finalize();

    string takeScreenshot();
    void removeAll();
    const list<string> getScreenshots() const;
    JValue toJson() const;
    string toString() const;

private:
    static void onDirChanged(GFileMonitor *monitor, GFile *file, GFile *other_file, GFileMonitorEvent event, gpointer user_data);

    bool loadScreenshots();

    LunaHandle* m_lunaHandle;
    list<string> m_screenshots;

    GFile* m_dir;
    GFileMonitor* m_dirMonitor;
    int m_dirMonitorId;
};

#endif
