// Copyright (c) 2022 LG Electronics, Inc.
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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* Expose definition of TEMP_FAILURE_RETRY */
#endif

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <linux/input.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <map>

#ifndef FALSE
#define FALSE   (0)
#endif

#ifndef TRUE
#define TRUE    (!FALSE)
#endif

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#define MAX(x,y) ((x) > (y) ? (x) : (y))
#define MIN(x,y) ((x) < (y) ? (x) : (y))

using namespace std;

/*
 * References:
 *     https://www.kernel.org/doc/Documentation/input/input.txt
 *     https://www.kernel.org/doc/Documentation/input/event-codes.txt
 *
 * The event structure itself
 *
 * struct input_event {
 *     struct timeval time;
 *     __u16 type;
 *     __u16 code;
 *     __s32 value;
 * };
 */

/*
 * NOTE
 *
 * struct record_format_payload is not marshalled for making it agnostic to machine endianness
 * print_input_packet() doesn't know about all kinds of input events --- but we do capture and record all of them
 *
 */

struct record_format_payload {
    char idev;
    struct input_event ie;
} __attribute__ ((__packed__));

struct input_event_node {
    struct input_event_node *next;
    struct record_format_payload rec;
};

struct input_event_list {
    struct input_event_node *head;
    struct input_event_node *tail;
};

/* The on-disk format assumes we'll have up to 256 (a char byte) devices listed here */
static const char *devnames[] = {
        "/dev/input/event0",
        "/dev/input/event1",
        "/dev/input/event2",
        "/dev/input/event3",
        "/dev/input/event4",
        "/dev/input/event5",
        "/dev/input/event6",
        "/dev/input/event7",
        "/dev/input/event8",
        "/dev/input/event9",
        "/dev/input/event10"
};
static const char dft_capture_path[] = "/tmp/input_capture.bin";
static struct input_event_list ielist = {NULL, NULL};
static volatile sig_atomic_t should_exit = 0;
static int fdev[ARRAY_SIZE(devnames)];
static int capture_file = -1;
static int playback_file = -1;
static int verbose = 0;

static map<int, string> keyevent_map = {
        { KEY_RESERVED,     "RESERVED" },   // 0
        { KEY_ESC,          "ESC" },        // 1
        { KEY_1,            "1" },          // 2
        { KEY_2,            "2" },          // 3
        { KEY_3,            "3" },          // 4
        { KEY_4,            "4" },          // 5
        { KEY_5,            "5" },          // 6
        { KEY_6,            "6" },          // 7
        { KEY_7,            "7" },          // 8
        { KEY_8,            "8" },          // 9
        { KEY_9,            "9" },          // 10
        { KEY_0,            "0" },          // 11
        { KEY_MINUS,        "-" },          // 12
        { KEY_EQUAL,        "=" },          // 13
        { KEY_BACKSPACE,    "BACKSPACE" },  // 14
        { KEY_TAB,          "TAB" },        // 15
        { KEY_Q,            "Q" },          // 16
        { KEY_W,            "W" },          // 17
        { KEY_E,            "E" },          // 18
        { KEY_R,            "R" },          // 19
        { KEY_T,            "T" },          // 20
        { KEY_Y,            "Y" },          // 21
        { KEY_U,            "U" },          // 22
        { KEY_I,            "I" },          // 23
        { KEY_O,            "O" },          // 24
        { KEY_P,            "P" },          // 25
        { KEY_LEFTBRACE,    "L-BRACE" },    // 26
        { KEY_RIGHTBRACE,   "R-BRACE" },    // 27
        { KEY_ENTER,        "ENTER" },      // 28
        { KEY_LEFTCTRL,     "L-CTRL" },     // 29
        { KEY_A,            "A" },          // 30
        { KEY_S,            "S" },          // 31
        { KEY_D,            "D" },          // 32
        { KEY_F,            "F" },          // 33
        { KEY_G,            "G" },          // 34
        { KEY_H,            "H" },          // 35
        { KEY_J,            "J" },          // 36
        { KEY_K,            "K" },          // 37
        { KEY_L,            "L" },          // 38
        { KEY_SEMICOLON,    ":" },          // 39
        { KEY_APOSTROPHE,   "'" },          // 40
        { KEY_GRAVE,        "`" },          // 41
        { KEY_LEFTSHIFT,    "L-SHIFT" },    // 42
        { KEY_BACKSLASH,    "\\" },         // 43
        { KEY_Z,            "Z" },          // 44
        { KEY_X,            "X" },          // 45
        { KEY_C,            "C" },          // 46
        { KEY_V,            "V" },          // 47
        { KEY_B,            "B" },          // 48
        { KEY_N,            "N" },          // 49
        { KEY_M,            "M" },          // 50
        { KEY_COMMA,        "," },          // 51
        { KEY_DOT,          ".", },         // 52
        { KEY_SLASH,        "/" },          // 53
        { KEY_RIGHTSHIFT,   "R-SHIFT" },    // 54
        { KEY_KPASTERISK,   "*" },          // 55
        { KEY_LEFTALT,      "L-ALT" },      // 56
        { KEY_SPACE,        "SPACE" },      // 57
        { KEY_CAPSLOCK,     "CAPSLOCK" },   // 58
        { KEY_F1,           "F1" },         // 59
        { KEY_F2,           "F2" },         // 60
        { KEY_F3,           "F3" },         // 61
        { KEY_F4,           "F4" },         // 62
        { KEY_F5,           "F5" },         // 63
        { KEY_F6,           "F6" },         // 64
        { KEY_F7,           "F7" },         // 65
        { KEY_F8,           "F8" },         // 66
        { KEY_F9,           "F9" },         // 67
        { KEY_F10,          "F10" },        // 68
        { KEY_NUMLOCK,      "NUMLOCK" },    // 69
        { KEY_SCROLLLOCK,   "SCROLLLOCK" }, // 70
        { KEY_F11,          "F11" },        // 87
        { KEY_F12,          "F12" },        // 88
        { KEY_RIGHTCTRL,    "R-CTRL" },     // 97
        { KEY_RIGHTALT,     "R-ALT" },      // 100
        { KEY_HOME,         "HOME" },       // 102
        { KEY_UP,           "KEY_UP" },     // 103
        { KEY_PAGEUP,       "PAGE_UP" },    // 104
        { KEY_LEFT,         "KEY_LEFT" },   // 105
        { KEY_RIGHT,        "KEY_RIGHT" },  // 106
        { KEY_END,          "END" },        // 107
        { KEY_DOWN,         "KEY_DOWN" },   // 108
        { KEY_PAGEDOWN,     "PAGE_DOWN" },  // 109
        { KEY_INSERT,       "INSERT" },     // 110
        { KEY_DELETE,       "DELETE" },     // 111
        { KEY_MUTE,         "MUTE" },       // 113
        { KEY_VOLUMEDOWN,   "VOLUME_DOWN"}, // 114
        { KEY_VOLUMEUP,     "VOLUME_UP"},   // 115
        { KEY_POWER,        "POWER" },      // 116
        { KEY_LEFTMETA,     "L-META" },     // 125
        { KEY_RIGHTMETA,    "R-META" },     // 126
        { KEY_COMPOSE,      "COMPOSE" },    // 127
        { KEY_MENU,         "MENU" },       // 139
        { KEY_HOMEPAGE,     "HOMEPAGE" },   // 172
        { BTN_LEFT,         "BTN_LEFT" },   // 272 0x110
        { BTN_RIGHT,        "BTN_RIGHT" },  // 273 0x111
        { BTN_MIDDLE,       "BTN_MIDDLE" }, // 274 0x112
        { BTN_TOUCH,        "BTN_TOUCH" },  // 330 0x14a
        { KEY_INFO,         "INFO" },       // 358 0x166
        { KEY_PROGRAM,      "PROGRAM" },    // 362 0x16a
        { KEY_FAVORITES,    "FAVORITES" },  // 364 0x16c
        { KEY_RED,          "RED" },        // 398 0x18e
        { KEY_GREEN,        "GREEN" },      // 399 0x18f
        { KEY_YELLOW,       "YELLOW" },     // 400 0x190
        { KEY_BLUE,         "BLUE" },       // 401 0x191
        { KEY_CHANNELUP,    "CHANNEL_UP" }, // 402 0x192
        { KEY_CHANNELDOWN,  "CHANNEL_DOWN" }, // 403 0x193
        { KEY_PREVIOUS,     "PREVIOUS" },   // 412 0x19c
        { 773,              "SMART_HOME" },
        { 1198,             "CURSOR_ON" },
        { 1199,             "CURSOR_OFF" },
};

static void sig_finish_handler(int sig)
{
    should_exit = (sig == sig);
}

static void open_devices_or_abort(int device_mode)
{
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(devnames); i++) {
        fdev[i] = open(devnames[i], device_mode);
        printf("Open device %s, fd %d\n", devnames[i], fdev[i]);
        if (fdev[i] == -1) {
            // It's okay failing to open some input devices; still we capture all possible events
            perror("Open device");
        }
    }
}

static void open_workset_files_or_abort(const char *capture_path, int device_mode, int capturefile_mode)
{
    // Open all files of interest
    printf("Open capture file %s\n", capture_path);
    capture_file = open(capture_path, capturefile_mode, 0644);
    if (capture_file == -1) {
        perror("Open capture file");
        exit(EXIT_FAILURE);
    }
    open_devices_or_abort(device_mode);
}

static int close_basic_fds(void)
{
    int basic_fds[] = {STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO};
    int ret = EXIT_SUCCESS;
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(basic_fds); i++) {
        if (basic_fds[i] != -1 && close(basic_fds[i]) != 0) {
            perror("Close close_all_files basic_fds");
            ret = EXIT_FAILURE;
        }
    }

    return ret;
}

static int close_all_files(void)
{
    int ret = EXIT_SUCCESS;
    unsigned int i;

    if (playback_file != -1 && close(playback_file) != 0) {
        perror("Close close_all_files playback_file");
        ret = EXIT_FAILURE;
    }
    if (capture_file != -1 && close(capture_file) != 0) {
        perror("Close close_all_files capture_file");
        ret = EXIT_FAILURE;
    }
    for (i = 0; i < ARRAY_SIZE(devnames); i++) {
        if (fdev[i] != -1 && close(fdev[i]) != 0) {
            perror("Close close_all_files device");
            ret = EXIT_FAILURE;
        }
    }
    if (close_basic_fds() == EXIT_FAILURE)
        ret = EXIT_FAILURE;

    return ret;
}

static void setup_termination_signals_or_abort(void)
{
    struct sigaction sa;

    sa.sa_flags = 0;
    sa.sa_handler = sig_finish_handler;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        perror("sigaction SIGINT");
        goto fail;
    }
    if (sigaction(SIGTERM, &sa, NULL) == -1) {
        perror("sigaction SIGTERM");
        goto fail;
    }

    return;
fail:
    close_all_files();
    exit(EXIT_FAILURE);
}

static int cleanup(const char *mode, int return_code)
{
    printf("Finished %s mode!\n", mode);
    // Release the input events list
    while (ielist.head != NULL) {
        struct input_event_node *next = ielist.head->next;

        free(ielist.head);
        ielist.head = next;
    }
    if (close_all_files() != EXIT_SUCCESS)
        return EXIT_FAILURE;

    return return_code;
}

static int find_input_device(const char *device_name)
{
    static const char EVT_PATTERN[] = "event";
    static const char N_PATTERN[] = "N: ";
    static const char H_PATTERN[] = "H: ";
    char *event, *line = NULL;
    size_t len;
    ssize_t read;
    int ret = -1, should_open = 0;

    FILE *stream = fopen("/proc/bus/input/devices", "r");
    if (stream == NULL)
        return ret;

    while ((read = getline(&line, &len, stream)) != -1) {
        if (strstr(line, N_PATTERN) == line) {
            should_open = 0;
            if (strstr(line + sizeof(N_PATTERN) - 1, device_name) != NULL) {
                // We found a line starting with 'N: ' containing the input device name
                should_open = 1;
            }
        } else if (should_open == 1 && strstr(line, H_PATTERN) == line
            && (event = strstr(line + sizeof(H_PATTERN) - 1, EVT_PATTERN)) != NULL) {
            // We found a line starting with 'H: ' containing the input device location in /dev/input/
            char *end_event;

            // Extract the ID from eventID name
            event += sizeof(EVT_PATTERN) - 1;
            end_event = event;
            while (isdigit(*end_event))
                end_event++;
            *end_event = '\0';

            // We'll return the open() result
            ret = open(devnames[atoi(event)], O_WRONLY | O_NONBLOCK);
            break;
        }
   }
   free(line);
   fclose(stream);

   return ret;
}

static void print_input_packet(struct record_format_payload *rec)
{
    struct input_event *ie = &rec->ie;
    const char *abs_format = "code %d (%s), value %d\n";

    if (!verbose)
        return;

    printf("Event: time %ld.%06ld, idev(%d), ", ie->time.tv_sec, ie->time.tv_usec, rec->idev);
    switch (ie->type) {
    case EV_SYN: // 0
        printf("--------------- SYN_REPORT ---------------\n");
        break;
    case EV_KEY: // 1
        printf("type %d (%s), code %d (%s), value %d (%s)\n",
                EV_KEY, "KEY",
                ie->code, (keyevent_map.find(ie->code) != keyevent_map.end()) ? keyevent_map[ie->code].c_str() : "",
                ie->value, (ie->value == 0) ? "RELEASE" : (ie->value == 1) ? "PRESS" : (ie->value == 2) ? "REPEAT" : "");
        break;
    case EV_REL: // 2
        printf("type %d (%s), code %d (%s), value %d %s\n",
                EV_REL, "REL",
                ie->code, (ie->code == REL_X) ? "REL_X" : (ie->code == REL_Y) ? "REL_Y" : (ie->code == REL_WHEEL) ? "REL_WHEEL" : (ie->code == REL_WHEEL_HI_RES) ? "REL_WHEEL_HI_RES" : "",
                ie->value, "");
        break;
    case EV_ABS: // 3
        printf("type %d (%s), ", EV_ABS, "ABS");
        switch (ie->code) {
        case ABS_X:
            printf(abs_format, ie->code, "ABS_X", ie->value);
            break;
        case ABS_Y:
            printf(abs_format, ie->code, "ABS_Y", ie->value);
            break;
        case ABS_Z:
            printf(abs_format, ie->code, "ABS_Z", ie->value);
            break;
        case ABS_MT_WIDTH_MAJOR:
            printf(abs_format, ie->code, "ABS_MT_WIDTH_MAJOR", ie->value);
            break;
        case ABS_MT_WIDTH_MINOR:
            printf(abs_format, ie->code, "ABS_MT_WIDTH_MINOR", ie->value);
            break;
        case ABS_MT_ORIENTATION:
            printf(abs_format, ie->code, "ABS_MT_ORIENTATION", ie->value);
            break;
        case ABS_MT_POSITION_X:
            printf(abs_format, ie->code, "ABS_MT_POSITION_X", ie->value);
            break;
        case ABS_MT_POSITION_Y:
            printf(abs_format, ie->code, "ABS_MT_POSITION_Y", ie->value);
            break;
        case ABS_MT_TRACKING_ID:
            printf(abs_format, ie->code, "ABS_MT_TRACKING_ID", ie->value);
            break;
        case ABS_MT_PRESSURE:
            printf(abs_format, ie->code, "ABS_MT_PRESSURE", ie->value);
            break;
        case ABS_MT_SLOT:
            printf(abs_format, ie->code, "ABS_MT_SLOT", ie->value);
            break;
        default:
            printf(abs_format, ie->code, "(UNKNOWN)", ie->value);
            break;
        }
        break;
    case EV_MSC: // 4
        printf("type %d (%s), code %d (%s), value 0x%x %s\n",
                EV_MSC, "MSC",
                ie->code, (ie->code == MSC_SCAN) ? "SCAN" : (ie->code == MSC_TIMESTAMP) ? "TIMESTAMP" : "",
                ie->value, "");
        break;
    case EV_LED: // 17
        printf("type %d (%s), code %d (%s), value 0x%x %s\n",
                EV_LED, "LED",
                ie->code, (ie->code == LED_NUML) ? "NUM_LOCK" : (ie->code == LED_CAPSL) ? "CAPS_LOCK" : (ie->code == LED_SCROLLL) ? "SCROLL_LOCK" : (ie->code == LED_MUTE) ? "MUTE" : "",
                ie->value, (ie->value == 1) ? "ON" : "OFF");
        break;
    case EV_REP: // 20
        printf("type %d (%s), code %d (%s), value 0x%x %s\n",
                EV_REP, "REP",
                ie->code, "",
                ie->value, "");
        break;
    default:
        printf("type %d (%s), code %d (%s), value 0x%x %s\n",
                ie->type, "UNKNOWN",
                ie->code, "UNKNWON",
                ie->value, "");
        break;
    }
}

static void flush_input_packets(void)
{
    struct input_event_node *currptr = ielist.head;

    // Ignore the tail element as it's always pre-allocated before trying to read
    while (currptr != ielist.tail) {
        struct input_event_node *next = currptr->next;

        if (TEMP_FAILURE_RETRY(write(capture_file, &currptr->rec, sizeof(currptr->rec))) != sizeof(currptr->rec)) {
            perror("write flush_input_packets record");
        }
        currptr = next;
    }
 }

static void queue_input_packet(struct input_event_node *ienode)
{
    if (ielist.head != NULL) {
        // Append to tail
        ielist.tail->next = ienode;
        ielist.tail = ienode;
    } else {
        // It's the first item
        ielist.head = ienode;
        ielist.tail = ienode;
    }
}

static struct input_event_node *get_new_node(void)
{
    struct input_event_node *ienode = (struct input_event_node*)malloc(sizeof(*ienode));

    if (ienode == NULL) {
        fprintf(stderr, "Error allocating memory for an input event record\n");
        return NULL;
    }
    ienode->next = NULL;

    return ienode;
}

static int read_input_packets_from_device(unsigned int idev)
{
    static struct input_event_node *ienode = NULL;
    ssize_t r;

    assert(idev <= 255 && idev < ARRAY_SIZE(devnames));

    if (ienode == NULL) {
        // Allocate an input event node if none or re-use the previous one (tail)
        if ((ienode = get_new_node()) == NULL) {
            return FALSE;
        }
        queue_input_packet(ienode);
    }
    ienode->rec.idev = idev;

    while ((r = TEMP_FAILURE_RETRY(read(fdev[idev], &ienode->rec.ie, sizeof(ienode->rec.ie)))) == sizeof(ienode->rec.ie)) {
        printf("%s | %zu bytes | ", devnames[idev], r);
        print_input_packet(&ienode->rec);
        if ((ienode = get_new_node()) == NULL) {
            return FALSE;
        }
        // Queue a new input event node in the tail
        queue_input_packet(ienode);
        ienode->rec.idev = idev;
    }
    if (r == -1 && errno != EAGAIN) {
        perror("Read read_input_packets_from_device");
        return FALSE;
    }

    return TRUE;
}

static void exec_input_packet(struct record_format_payload *rec)
{
    int dest_fd;

    if (playback_file != -1) {
        // We will override the destination device
        dest_fd = playback_file;
    } else {
        unsigned int idx = rec->idev;
        assert(idx < ARRAY_SIZE(devnames));
        dest_fd = fdev[idx];
    }

    if (TEMP_FAILURE_RETRY(write(dest_fd, &rec->ie, sizeof(rec->ie))) != sizeof(rec->ie))
        perror("Write exec_input_packet");
}

static int read_input_packets_from_file(unsigned int capture_file_fd)
{
    struct input_event_node *ienode = NULL;
    ssize_t r = 0;

    if ((ienode = get_new_node()) == NULL) {
        return FALSE;
    }
    queue_input_packet(ienode);

    while (!should_exit && ((r = TEMP_FAILURE_RETRY(read(capture_file_fd, &ienode->rec, sizeof(ienode->rec)))) == sizeof(ienode->rec))) {
        if ((ienode = get_new_node()) == NULL) {
            return FALSE;
        }
        queue_input_packet(ienode);
    }
    if (r == -1 && errno != EAGAIN) {
        perror("Read read_input_packets_from_file");
        return FALSE;
    }

    return TRUE;
}

static int playback_mode(const char *capture_path)
{
    struct input_event_node *currptr;
    struct timespec t1, t2;
    struct timeval basetime;
    int ret = EXIT_SUCCESS;

    open_workset_files_or_abort(capture_path, O_WRONLY | O_NONBLOCK, O_RDONLY);

    setup_termination_signals_or_abort();

    if (!read_input_packets_from_file(capture_file)) {
        ret = EXIT_FAILURE;
        goto exit;
    }

    // Ignore the tail element as it's always pre-allocated before trying to read
    currptr = ielist.head;
    if (currptr == ielist.tail) {
        // Nothing to do as no input packet was read from empty file
        goto exit;
    }
    // We obtain the basetime from the first packet
    memcpy(&basetime, &currptr->rec.ie.time, sizeof(basetime));
    print_input_packet(&currptr->rec);
    // difference of t1 and t2 is the elapsed time we spent executing the previous packet
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &t1) != 0) {
        perror("Read raw monotonic clock 1");
        ret = EXIT_FAILURE;
        goto exit;
    }
    exec_input_packet(&currptr->rec);

    currptr = currptr->next;
    while (!should_exit && currptr != ielist.tail) {
        struct timeval t1val, t2val, monodiff, timediff;
        unsigned int usecs;

        if (clock_gettime(CLOCK_MONOTONIC_RAW, &t2) != 0) {
            perror("Read raw monotonic clock 2");
            ret = EXIT_FAILURE;
            goto exit;
        }
        TIMESPEC_TO_TIMEVAL(&t1val, &t1);
        TIMESPEC_TO_TIMEVAL(&t2val, &t2);
        // monodiff stores MONOTONIC elapsed time between t1 and t2
        timersub(&t2val, &t1val, &monodiff);
        memcpy(&t1, &t2, sizeof(t1));
        // timediff stores the difference between current packet time and previous basetime
        timersub(&currptr->rec.ie.time, &basetime, &timediff);
        memcpy(&basetime, &currptr->rec.ie.time, sizeof(basetime));
        if (timercmp(&timediff, &monodiff, >)) {
            struct timeval finaldiff;

            // Only sleep if we didn't spend more time executing previous packet than the time we should originally wait
            timersub(&timediff, &monodiff, &finaldiff);
            usecs = finaldiff.tv_sec * 1000000 + finaldiff.tv_usec;
            printf("Sleeping %4u.%06u\n", usecs / 1000000, usecs % 1000000);
            usleep(usecs);
        }
        // Reset the packet timestamp read from the capture file
        currptr->rec.ie.time.tv_sec  = 0;
        currptr->rec.ie.time.tv_usec = 0;

        print_input_packet(&currptr->rec);
        exec_input_packet(&currptr->rec);
        currptr = currptr->next;
    }
exit:
    return cleanup("playback", ret);
}

static int capture_mode(const char *capture_path)
{
    int nfds = 0, ret = EXIT_SUCCESS;
    sigset_t sigmask;
    fd_set orig_rd;
    unsigned int i;

    open_workset_files_or_abort(capture_path, O_RDONLY | O_NONBLOCK, O_CREAT | O_WRONLY | O_TRUNC);

    // Block signals of interest
    sigemptyset(&sigmask);
    sigaddset(&sigmask, SIGINT);
    sigaddset(&sigmask, SIGTERM);
    if (sigprocmask(SIG_BLOCK, &sigmask, NULL) == -1) {
        perror("sigprocmask SIG_BLOCK");
        ret = EXIT_FAILURE;
        goto exit;
    }

    setup_termination_signals_or_abort();

    // Setup pselect parameters to listen to input devices plus signal interruptions
    sigemptyset(&sigmask);
    FD_ZERO(&orig_rd);
    for (i = 0; i < ARRAY_SIZE(devnames); i++) {
        if (fdev[i] == -1) continue;
        FD_SET(fdev[i], &orig_rd);
        nfds = MAX(nfds, fdev[i]);
    }

    while (!should_exit) {
        fd_set rd;
        int r;

        // Restore the original set with all input devices of interest
        memcpy(&rd, &orig_rd, sizeof(rd));

        // Block until an event of interest comes from input devices or signal interruptions
        r = pselect(nfds + 1, &rd, NULL, NULL, NULL, &sigmask);
        if (r == -1) {
            if (errno == EINTR) {
                // Got interrupted when waiting for events
                printf("We were interrupted by a signal\n");
                continue;
            }
            // Error when waiting for events
            perror("pselect capture_mode");
            ret = EXIT_FAILURE;
            break;
        }
        // Handle available events
        for (i = 0; i < ARRAY_SIZE(devnames); i++) {
            if (fdev[i] == -1) continue;
            if (FD_ISSET(fdev[i], &rd)) {
                if (!read_input_packets_from_device((unsigned int)i)) {
                    ret = EXIT_FAILURE;
                    goto exit;
                }
            }
        }
    }
exit:
    flush_input_packets();
    return cleanup("capture", ret);
}

static int print_usage(char *progname)
{
    fprintf(stderr,
            "Usage: %s [-h] [-v] [-d device_name] [-m [capture|playback]] path-to-capture-file"
            "\n\t-h: help\n\t-v: verbose mode\n\t-d: device name from /proc/bus/input/devices (N)\n\t-m: execution mode [capture|playback]"
            "\n\tpath-to-capture-file\n",
            progname);
    return EXIT_FAILURE;
}

int main(int argc, char *argv[])
{
    const char error_msg[] = "One of 'capture' or 'playback' modes must be specified";
    const char *capture_path = dft_capture_path;
    char device_name[PATH_MAX] = "", read_path[PATH_MAX];
    char *exec_mode = NULL;
    int opt;

    while ((opt = getopt(argc, argv, "hvm:d:")) != -1) {
        switch (opt) {
        case 'h':
            exit(print_usage(argv[0]));
            break;
        case 'v':
            verbose = 1;
            break;
        case 'd':
            strncpy(device_name, optarg, sizeof(device_name) - 1);
            device_name[sizeof(device_name) - 1] = '\0';
            break;
        case 'm':
            exec_mode = optarg;
            break;
        default: /* '?' */
            exit(print_usage(argv[0]));
        }
    }

    if (exec_mode == NULL) {
        fprintf(stderr, "Missing argument: %s\n", error_msg);
        exit(print_usage(argv[0]));
    }

    if (optind < argc) {
        strncpy(read_path, argv[optind], sizeof(read_path) - 1);
        read_path[sizeof(read_path) - 1] = '\0';
        capture_path = read_path;
    }

    if (device_name[0] != '\0') {
        int ret = find_input_device(device_name);

        if (ret == -1) {
            fprintf(stderr, "Could not find device[%s] in /proc/bus/input/devices; aborting.\n", device_name);
            exit(EXIT_FAILURE);
        }
        playback_file = ret;
    }

    if (!verbose) {
        // If not in verbose mode, close std[out|in|err] upfront
        close_basic_fds();
    }

    printf("Mode %s, CapturePath %s\n", exec_mode, capture_path);

    if (strncmp(exec_mode, "capture", sizeof("capture")) == 0) {
        exit(capture_mode(capture_path));
    } else if (strncmp(exec_mode, "playback", sizeof("playback")) == 0) {
        exit(playback_mode(capture_path));
    }
    fprintf(stderr, "Invalid argument: %s\n", error_msg);
    exit(print_usage(argv[0]));
}
