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

#include "File.h"

#include <dirent.h>
#include <glib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

string File::readFile(const string& file_name)
{
    ifstream file(file_name.c_str(), ifstream::in);
    string file_contents;

    if (file.is_open() && file.good()) {
        istreambuf_iterator<char> begin(file), end;
        file_contents = string(begin, end);
    }

    return file_contents;
}

bool File::writeFile(const string& path, const string& buffer)
{
    ofstream file(path.c_str());
    if (file.is_open()) {
        file << buffer;
        file.close();
    } else {
        return false;
    }
    return true;
}

bool File::concatToFilename(const string originPath, string& returnPath, const string addingStr)
{
    if (originPath.empty() || addingStr.empty())
        return false;

    returnPath = "";

    string dir_path, filename, name_only, ext;
    size_t pos_dir = originPath.find_last_of("/");

    if (string::npos == pos_dir) {
        filename = std::move(originPath);
    } else {
        pos_dir = pos_dir + 1;
        dir_path = originPath.substr(0, pos_dir);
        filename = originPath.substr(pos_dir);
    }

    size_t pos_ext = filename.find_last_of(".");

    if (string::npos == pos_ext)
        return false;

    name_only = filename.substr(0, pos_ext);
    ext = filename.substr(pos_ext);

    if (ext.length() < 2)
        return false;

    returnPath = dir_path + name_only + addingStr + ext;

    return true;
}

bool File::isDirectory(const string& path)
{
    struct stat dirStat;
    if (stat(path.c_str(), &dirStat) != 0 || (dirStat.st_mode & S_IFDIR) == 0) {
        return false;
    }
    return true;
}

bool File::isFile(const string& path)
{
    struct stat fileStat;

    if (stat(path.c_str(), &fileStat) != 0 || (fileStat.st_mode & S_IFREG) == 0) {
        return false;
    }
    return true;
}

bool File::createFile(const string& path)
{
    return File::writeFile(path, "");
}

// createDir(const string& path) version may hide errno during path.c_str().
bool File::createDir(const char* path)
{
    return (0 == g_mkdir_with_parents(path, 0770));
}

bool File::removeDir(const string& path)
{
    string command = "rm -rf " + path;
    int rc;
    string errmsg;
    return system(command, &rc, errmsg) && WIFEXITED(rc) && WEXITSTATUS(rc) == 0;
}

bool File::listFiles(const string& path, list<string>& files)
{
    DIR *dir;
    struct dirent *dirent;
    if ((dir = opendir(path.c_str())) != NULL) {
        while ((dirent = readdir(dir)) != NULL) {
            if (strcmp(".", dirent->d_name) == 0)
                continue;
            if (strcmp("..", dirent->d_name) == 0)
                continue;
            files.emplace_back(dirent->d_name);
        }
        (void)closedir(dir);
        return true;
    }
    return false;
}

string File::join(const string& a, const string& b)
{
    if (a.empty() || b.empty()) {
        return "";
    }

    string path = "";

    if (a.back() == '/') {
        if (b.front() == '/') {
            path = a + b.substr(1);
        } else {
            path = a + b;
        }
    } else {
        if (b.front() == '/') {
            path = a + b;
        } else {
            path = a + "/" + b;
        }
    }
    return path;
}

bool File::popen(const string& command, string& out, string& err, int* exitStatus, string& error)
{
    gchar* g_out = NULL;
    gchar* g_err = NULL;
    gint g_exitStatus;
    GError* g_error = NULL;
    if (!g_spawn_command_line_sync(command.c_str(), &g_out, &g_err, &g_exitStatus, &g_error)) {
        if (g_error && g_error->message) {
            error = g_error->message;
            g_error_free(g_error);
        } else {
            error = "";
        }
        return false;
    }
    if (exitStatus) {
        *exitStatus = g_exitStatus;
    }
    if (g_out) {
        out = g_out;
        g_free(g_out);
    } else {
        out = "";
    }
    if (g_err) {
        err = g_err;
        g_free(g_err);
    } else {
        err = "";
    }
    return true;
}

bool File::system(const string& command, int* exitStatus, string& error)
{
    gint g_exitStatus;
    GError* g_error = NULL;
    if (!g_spawn_command_line_sync(command.c_str(), NULL, NULL, &g_exitStatus, &g_error)) {
        if (g_error && g_error->message) {
            error = g_error->message;
            g_error_free(g_error);
        } else {
            error = "";
        }
        return false;
    }
    if (exitStatus) {
        *exitStatus = g_exitStatus;
    }
    return true;
}

File::File()
{
}

File::~File()
{
}
