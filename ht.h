#ifndef HT_H_
#define HT_H_

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <assert.h>
#include <netdb.h>
#include <sys/epoll.h>
#include <unistd.h>

#ifndef HOST
#define HOST "echo.free.beeceptor.com"
#endif

#ifndef PORT
#define PORT 80
#endif

#ifndef MAX_HEADER_KEY_LEN
#define MAX_HEADER_KEY_LEN 32
#endif

#ifndef MAX_HEADER_VAL_LEN
#define MAX_HEADER_VAL_LEN 128
#endif

#ifndef MAX_HTTP_BODY_LEN
#define MAX_HTTP_BODY_LEN (8 * 1024)
#endif

#ifndef MAX_CUSTOM_HEADER_LENGTH
#define MAX_CUSTOM_HEADER_LENGTH 1024
#endif

#ifndef MAX_EPOLL_EVENTS
#define MAX_EPOLL_EVENTS 4
#endif

#ifndef MAX_FD
#define MAX_FD 4
#endif

typedef enum {
    HT_GET,
    HT_POST,
} HTTP_TYPE;

typedef enum {
    HT_SEC_TITLE,
    HT_SEC_HEADER,
    HT_SEC_BODY,
    HT_SEC_NO_BODY,
    HT_SEC_END,
} HTTP_SECTION;

typedef enum {
    HT_ERR_CONNECTION,
    HT_ERR_HOST,
    HT_ERR_SOCKET,
} HT_ERR;

typedef struct {
    char data[MAX_HEADER_KEY_LEN];
} ht_Header_Key;

typedef struct {
    char data[MAX_HEADER_VAL_LEN];
} ht_Header_Value;

typedef struct {
    ht_Header_Key* keys;
    ht_Header_Value* vals;
    int capacity;
    int count;
} ht_headers;

#define MAX_VERSION_LEN 9
#define MAX_STATUS_TEXT_LEN 32

typedef struct {
    char status[MAX_STATUS_TEXT_LEN];
    char version[MAX_VERSION_LEN];
    int code;
} ht_Status_Line;

typedef struct {
    char body[MAX_HTTP_BODY_LEN];
    ht_Status_Line status;
    ht_headers headers;
} ht_Message;

typedef struct {
    int items[MAX_EPOLL_EVENTS];
    int count;
} ht_active_events;

const char* ht_build_request_data(HTTP_TYPE type, const char* path, const char* data);
#define ht_build_request(type, path) ht_build_request_data(type, path, NULL)

int ht_init(void);
int ht_send(const char* request);
ht_active_events ht_poll(int timeout);
bool ht_poll_fd(int fd, int timeout);
char* ht_get_response_from_fd(int fd);
ht_Message ht_message(const char* buf, size_t buf_size);
void ht_add_custom_header(const char* key, const char* value);
void ht_close_all(void);
void ht_free(ht_Message ht);

typedef struct {
    int epfd;
    int listened_file_count;
    int available_fd_count;
    int available_fds[MAX_FD];
    char custom_headers[MAX_CUSTOM_HEADER_LENGTH];
} ht_Snapshot;

ht_Snapshot ht_snapshot(void);
void ht_restore(ht_Snapshot snapshot);
#endif // HT_H_

#ifdef HT_IMPLEMENTATION

#include <ctype.h>

typedef struct {
    const char* data;
    size_t count;
} ht_sv;

ht_sv ht_sv_from_buffer(const char* buffer, size_t count)
{
    ht_sv sv;
    sv.data = buffer;
    sv.count = count;
    return sv;
}

ht_sv ht_sv_split_once(ht_sv* sv, char delim)
{
    size_t i = 0;
    while (i < sv->count && sv->data[i] != delim) {
        i += 1;
    }

    ht_sv result = ht_sv_from_buffer(sv->data, i);

    if (i < sv->count) {
        sv->count -= i + 1;
        sv->data += i + 1;
    } else {
        sv->count -= i;
        sv->data += i;
    }

    return result;
}

ht_sv ht_sv_split_from_left(ht_sv* sv, size_t size)
{
    ht_sv result = ht_sv_from_buffer(sv->data, size);

    if (size < sv->count) {
        sv->count -= size + 1;
        sv->data += size + 1;
    } else {
        sv->count -= size;
        sv->data += size;
    }

    return result;
}

ht_sv ht_sv_trim(ht_sv sv)
{
    size_t l = 0;
    while (l < sv.count && isspace(sv.data[l])) {
        l += 1;
    }
    sv.data += l;
    assert(sv.count - l >= 0 && "String count can never be negative");
    sv.count -= l;

    size_t r = 0;
    while (r < sv.count && isspace(sv.data[sv.count - r - 1])) {
        r += 1;
    }
    assert(sv.count - r >= 0 && "String count can never be negative");
    sv.count -= r;

    return ht_sv_from_buffer(sv.data, sv.count);
}

int ht_sv_to_int(ht_sv sv, int base)
{
    char dec[sv.count + 1];
    strncpy(dec, sv.data, sv.count);
    dec[sv.count] = '\0';
    size_t len = strtol(dec, NULL, base);
    return len;
}

ht_Status_Line ht_status_line(ht_sv v, ht_sv c, ht_sv t)
{
    ht_Status_Line st;
    v = ht_sv_trim(v);
    c = ht_sv_trim(c);
    t = ht_sv_trim(t);
    memcpy(&st.version, v.data, v.count);
    memcpy(&st.status, t.data, t.count);
    st.code = ht_sv_to_int(c, 10);
    return st;
}

static char __ht_custom_headers[MAX_CUSTOM_HEADER_LENGTH];
void ht_add_custom_header(const char* key, const char* value)
{
    assert(strlen(key) + strlen(value) + 5 < MAX_CUSTOM_HEADER_LENGTH
        && "Custom header length is too long!");
    strcat(__ht_custom_headers, key);
    strcat(__ht_custom_headers, ": ");
    strcat(__ht_custom_headers, value);
    strcat(__ht_custom_headers, "\r\n");
}

const char* ht_build_request_data(HTTP_TYPE type, const char* resource, const char* data)
{
#ifndef MAX_REQUEST_BUFFERS
#define MAX_REQUEST_BUFFERS 4
#endif
#ifndef MAX_REQUEST_BUFFER_LENGTH
#define MAX_REQUEST_BUFFER_LENGTH 1024
#endif

    static char buffers[MAX_REQUEST_BUFFERS][MAX_REQUEST_BUFFER_LENGTH] = { 0 };
    static int index = 0;

    char* currentBuffer = buffers[index];
    memset(currentBuffer, 0, MAX_REQUEST_BUFFER_LENGTH);

    switch (type) {
    case HT_GET:
        snprintf(currentBuffer, MAX_REQUEST_BUFFER_LENGTH,
            "GET %s HTTP/1.1\r\n"
            "Host: " HOST "\r\n"
            "%s"
            "Accept-Encoding: Chunked\r\n"
            "\r\n"
            "\r\n",
            resource, __ht_custom_headers);
        break;
    case HT_POST:
        snprintf(currentBuffer, MAX_REQUEST_BUFFER_LENGTH,
            "POST %s HTTP/1.1\r\n"
            "Host: " HOST "\r\n"
            "%s"
            "Accept-Encoding: Chunked\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: %lu\r\n"
            "\r\n"
            "%s"
            "\r\n",
            resource, __ht_custom_headers, strlen(data), data);
        break;
    default:
        return NULL;
    }

    if (++index >= MAX_REQUEST_BUFFERS) {
        index = 0;
    }

    return currentBuffer;
}

static int __ht_epoll_fd = -1;
static int __ht_events_ready = 0;

static int __ht_listened_files = 0;

static int __ht_available_fd[MAX_FD];
static int __ht_available_fd_count = 0;

static struct epoll_event __ht_events_queue[MAX_EPOLL_EVENTS];

int ht_init(void)
{
    __ht_epoll_fd = -1;
    __ht_events_ready = 0;

    __ht_listened_files = 0;

    __ht_epoll_fd = epoll_create1(0);
    if (__ht_epoll_fd == -1) {
        printf("ERROR: Couldn't create epoll instance!\n");
    }
    printf("INFO: Created epoll instance with fd = %d !\n", __ht_epoll_fd);
    return __ht_epoll_fd;
}

void ht_restore(ht_Snapshot snap)
{
    printf("INFO: Restoring ht...\n");
    __ht_epoll_fd = snap.epfd;
    __ht_listened_files = snap.listened_file_count;
    memcpy(__ht_custom_headers, snap.custom_headers, MAX_CUSTOM_HEADER_LENGTH);
    __ht_available_fd_count = snap.available_fd_count;
    memcpy(__ht_available_fd, snap.available_fds, snap.available_fd_count);
    printf("INFO: __ht_epoll_fd = %d\n", __ht_epoll_fd);
    printf("INFO: __ht_listened_files = %d\n", __ht_listened_files);
    printf("INFO: __ht_custom_headers = %s\n", __ht_custom_headers);
    printf("INFO: __ht_available_fd_count = %d\n", __ht_available_fd_count);
    printf("INFO: __ht_available_fd = ");
    for (int i = 0; i < __ht_available_fd_count; i++) {
        printf("%d, ", __ht_available_fd[i]);
    }
    printf("\n");
    printf("INFO: Restored succesfully.\n");
}

ht_Snapshot ht_snapshot(void)
{
    ht_Snapshot snap = {
        .epfd = __ht_epoll_fd,
        .listened_file_count = __ht_listened_files,
        .available_fd_count = __ht_available_fd_count,
    };
    memcpy(snap.custom_headers, __ht_custom_headers, MAX_CUSTOM_HEADER_LENGTH);
    memcpy(snap.available_fds, __ht_available_fd, MAX_FD);
    return snap;
}

int ht_send(const char* request)
{
    int fd;
    if (__ht_available_fd_count > 0) {
        fd = __ht_available_fd[--__ht_available_fd_count];
        int error = 0;
        socklen_t len = sizeof(error);
        int retval = getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len);
        if (retval != 0) {
            fprintf(stderr, "ERROR: Socket error retval: %s\n", strerror(retval));
            return -1;
        }
        if (error != 0) {
            fprintf(stderr, "ERROR: Socket error error: %s\n", strerror(error));
            return -1;
        }
    } else {
        static struct sockaddr_in serv_addr;
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(PORT);

        struct hostent* host_entry = gethostbyname(HOST);
        if (host_entry == NULL) {
            printf("\nERROR:  Host entry error \n");
            return -1;
        }

        if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            printf("\nERROR:  Socket creation error \n");
            return -1;
        }

        const char* ip_buff = inet_ntoa(*((struct in_addr*)host_entry->h_addr_list[0]));
        if (inet_pton(AF_INET, ip_buff, &serv_addr.sin_addr) <= 0) {
            printf("\nERROR: Invalid address/ Address not supported \n");
            return -1;
        }

        int status;
        if ((status = connect(fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr))) < 0) {
            printf("\nERROR: Connection Failed : %d\n", status);
            return -1;
        }
    }

    struct epoll_event einf[1];
    memset(&einf[0], 0, sizeof(struct epoll_event));
    einf[0].events = EPOLLIN;
    einf[0].data.fd = fd;

    if (epoll_ctl(__ht_epoll_fd, EPOLL_CTL_ADD, fd, &einf[0]) == 0) {
        printf("INFO: Added fd = %d to epoll.\n", fd);
        __ht_listened_files++;
    } else {
        printf("ERROR: epfd = %d\n", __ht_epoll_fd);
        printf("ERROR: fd = %d\n", fd);
        assert(false && "Couldnt add fd to epoll");
    }

    size_t req_size = strlen(request);
    size_t written = write(fd, request, req_size);
    assert(written == req_size && "ERROR: Couldnt write the whole request.");
    printf("INFO: Sent message to fd = %d with length: %zu\n", fd, written);
    return fd;
}

bool ht_poll_fd(int fd, int timeout)
{
    __ht_events_ready = epoll_wait(__ht_epoll_fd, __ht_events_queue, MAX_EPOLL_EVENTS, timeout);
    for (int i = 0; i < __ht_events_ready; i++) {
        if (__ht_events_queue[i].data.fd == fd) {
            return true;
        }
    }
    return false;
}

ht_active_events ht_poll(int timeout)
{
    __ht_events_ready = epoll_wait(__ht_epoll_fd, __ht_events_queue, MAX_EPOLL_EVENTS, timeout);
    ht_active_events res;
    res.count = __ht_events_ready;
    for (int i = 0; i < __ht_events_ready; i++) {
        res.items[i] = __ht_events_queue[i].data.fd;
    }
    return res;
}

char* ht_get_response_from_fd(int fd)
{
    size_t total_read = 0;
    size_t buf_size = 1024;
    char* buf = malloc(buf_size);
    while (true) {
        size_t current_read = read(fd, buf + total_read, buf_size - total_read);
        total_read += current_read;
        if (total_read == buf_size) {
            buf_size *= 2;
            buf = realloc(buf, sizeof(char) * buf_size);
        } else {
            break;
        }
    }
    buf[total_read] = '\0';

    if (epoll_ctl(__ht_epoll_fd, EPOLL_CTL_DEL, fd, NULL) == 0) {
        __ht_listened_files -= 1;
        printf("INFO: Removed fd = %d from epoll list.\n", fd);
    }

    if (__ht_available_fd_count < MAX_FD) {
        __ht_available_fd[__ht_available_fd_count++] = fd;
    } else if (close(fd) == 0) {
        printf("INFO: Closed fd = %d succesfully.\n", fd);
    }

    return buf;
}

ht_Message ht_message(const char* buf, size_t buf_size)
{
    size_t total_read = strlen(buf);
    assert(total_read <= buf_size && "Buffer is not null terminated.");
    assert(buf_size < MAX_HTTP_BODY_LEN && "HTTP message is too long.");

    ht_sv response = ht_sv_from_buffer(buf, strlen(buf));

    HTTP_SECTION section = HT_SEC_TITLE;
    size_t total_body_len = 0;
    size_t body_written = 0;

    ht_Message h;
    h.headers.count = 0;
    h.headers.capacity = 8;
    h.headers.keys = (ht_Header_Key*)calloc(h.headers.capacity, sizeof(ht_Header_Key));
    h.headers.vals = (ht_Header_Value*)calloc(h.headers.capacity, sizeof(ht_Header_Value));
    memset(h.body, 0, MAX_HTTP_BODY_LEN);

    while (response.count > 0 && section != HT_SEC_END) {
        ht_sv chop = ht_sv_split_once(&response, '\n');
        switch (section) {
        case HT_SEC_TITLE: {
            ht_sv ver = ht_sv_split_once(&chop, ' ');
            ht_sv code = ht_sv_split_once(&chop, ' ');
            ht_sv st = chop;

            h.status = ht_status_line(ver, code, st);

            section = HT_SEC_HEADER;
            break;
        }
        case HT_SEC_HEADER: {
            chop = ht_sv_trim(chop);
            if (chop.count <= 1) {
                if (h.status.code == 400 || h.status.code == 500) {
                    section = HT_SEC_NO_BODY;
                } else {
                    section = HT_SEC_BODY;
                }
                break;
            }
            ht_sv key = ht_sv_split_once(&chop, ':');
            ht_sv val = ht_sv_trim(chop);
            if (h.headers.count + 2 >= h.headers.capacity) {
                h.headers.capacity *= 2;
                h.headers.vals = (ht_Header_Value*)realloc(
                    h.headers.vals, sizeof(ht_Header_Value) * h.headers.capacity);
                h.headers.keys = (ht_Header_Key*)realloc(
                    h.headers.keys, sizeof(ht_Header_Key) * h.headers.capacity);
            }
            assert(key.count < MAX_HEADER_KEY_LEN && "Header key is too long.");
            memcpy(&h.headers.keys[h.headers.count].data, key.data, key.count);
            assert(val.count < MAX_HEADER_VAL_LEN && "Header value is too long.");
            memcpy(&h.headers.vals[h.headers.count].data, val.data, val.count);
            h.headers.count++;
            break;
        }
        case HT_SEC_BODY: {
            ht_sv length = ht_sv_trim(chop);
            char hex_cstr[length.count + 1];
            strncpy(hex_cstr, length.data, length.count);
            size_t len = ht_sv_to_int(length, 16);
            total_body_len += len;
            if (len == 0) {
                section = HT_SEC_END;
                break;
            }
            chop = ht_sv_split_from_left(&response, len);
            chop = ht_sv_trim(chop);
            assert(total_body_len <= total_read
                && "We are writing more data than we got");
            assert(chop.count == len
                && "Chop has less data than it should have");
            memcpy(&h.body[body_written], chop.data, len);
            body_written += len;
            break;
        }
        case HT_SEC_NO_BODY: {
            chop = ht_sv_trim(chop);
            assert(total_body_len <= total_read
                && "We are writing more data than we got");
            memcpy(&h.body[body_written], chop.data, chop.count);
            body_written += chop.count;
            section = HT_SEC_END;
        }
        case HT_SEC_END:
            break;
        }
    }
    return h;
}

void ht_free(ht_Message ht)
{
    free(ht.headers.keys);
    free(ht.headers.vals);
}

void ht_close_all(void)
{
    while (__ht_listened_files > 0) {
        __ht_events_ready = epoll_wait(__ht_epoll_fd, __ht_events_queue, MAX_EPOLL_EVENTS, -1);
        for (int i = 0; i < __ht_events_ready; i++) {
            int fd = __ht_events_queue[i].data.fd;
            if (epoll_ctl(__ht_epoll_fd, EPOLL_CTL_DEL, fd, NULL) == 0) {
                printf("INFO: Removed fd = %d from epoll list.\n", fd);
            } else {
                printf("ERROR: Removing fd = %d from epoll list.\n", fd);
            }
            if (close(fd) == 0) {
                printf("INFO: Closed fd = %d succesfully.\n", fd);
            } else {
                printf("ERROR: Couldnt close fd = %d.\n", fd);
            }
            __ht_listened_files--;
        }
    }
    for (int i = 0; i < __ht_available_fd_count; i++) {
        int fd = __ht_available_fd[i];
        if (close(fd) == 0) {
            printf("INFO: Closed fd = %d succesfully.\n", fd);
        } else {
            printf("ERROR: Couldnt close fd = %d.\n", fd);
        }
    }
}

#endif // HT_IMPLEMENTATION
