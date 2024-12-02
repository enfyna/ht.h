#ifndef HT_H_
#define HT_H_

#include <ctype.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <assert.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/poll.h>
#include <unistd.h>

#ifndef HOST
#define HOST "github.com"
#endif

#ifndef PORT
#define PORT 80
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
    const char* data;
    size_t count;
} ht_sv;

typedef struct {
    ht_sv* keys;
    ht_sv* vals;
    int capacity;
    int count;
} ht_headers;

typedef struct {
    char* all;
    ht_sv version;
    int st_code;
    ht_sv st_message;
    ht_headers headers;
    ht_sv body;
} ht_message;

typedef struct {
    struct pollfd poll;

    char* buffer;
    size_t buf_size;

    size_t total_read;
    size_t last_read;
    bool waiting;
    bool received;
    bool working;
    int polled_for;
} ht_worker;

const char* ht_build_request(HTTP_TYPE type, const char* path);
ht_worker* ht_init(void);
bool ht_send(ht_worker* htt, const char* request);
bool ht_poll(ht_worker* htt, int timeout);
ht_message* ht_get_response(ht_worker* http);
void ht_worker_clean(ht_worker* http);
void ht_worker_free(ht_worker* http);

ht_sv ht_sv_trim(ht_sv sv);
ht_sv ht_sv_split_once(ht_sv* sv, char delim);
ht_sv ht_sv_from_buffer(const char* buffer, size_t count);
int ht_sv_to_int(ht_sv sv, int base);
#endif // HT_H_

#define HT_IMPLEMENTATION
#ifdef HT_IMPLEMENTATION

ht_sv ht_sv_from_buffer(const char* buffer, size_t count) {
    ht_sv sv;
    sv.data = buffer;
    sv.count = count;
    return sv;
}

ht_sv ht_sv_split_once(ht_sv* sv, char delim) {
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

ht_sv ht_sv_split_from_left(ht_sv* sv, size_t size) {
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

ht_sv ht_sv_trim(ht_sv sv) {
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

int ht_sv_to_int(ht_sv sv, int base) {
    char dec[sv.count + 1];
    strncpy(dec, sv.data, sv.count);
    dec[sv.count] = '\0';
    size_t len = strtol(dec, NULL, base);
    return len;
}

const char* ht_type_to_cstr(HTTP_TYPE type) {
    switch (type) {
    case HT_POST:
        return "POST";
    case HT_GET:
        return "GET";
    default:
        return NULL;
    }
}

const char* ht_build_request(HTTP_TYPE type, const char* resource) {
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

    snprintf(currentBuffer, MAX_REQUEST_BUFFER_LENGTH,
        "%s %s HTTP/1.1\r\n"
        "Host: " HOST "\r\n"
        "\r\n"
        "\r\n",
        ht_type_to_cstr(type), resource);

    if (++index >= MAX_REQUEST_BUFFERS) {
        index = 0;
    }

    return currentBuffer;
}

ht_worker* ht_init(void) {

#ifndef BUFF_SIZE
#define BUFF_SIZE 1024
#endif

    ht_worker* htt = (ht_worker*)malloc(sizeof(ht_worker));
    htt->poll.events = POLLIN;

    htt->buffer = (char*)calloc(BUFF_SIZE, sizeof(char));
    htt->buf_size = BUFF_SIZE;

    htt->total_read = 0;
    htt->last_read = 0;
    htt->polled_for = 0;
    htt->waiting = true;
    htt->received = false;
    htt->working = false;

    static struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    struct hostent* host_entry = gethostbyname(HOST);
    if (host_entry == NULL) {
        printf("\nERROR:  Host entry error \n");
        ht_worker_free(htt);
        return NULL;
    }

    char* ip_buff = inet_ntoa(*((struct in_addr*)host_entry->h_addr_list[0]));

    if ((htt->poll.fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\nERROR:  Socket creation error \n");
        ht_worker_free(htt);
        return NULL;
    }

    if (inet_pton(AF_INET, ip_buff, &serv_addr.sin_addr) <= 0) {
        printf("\nERROR: Invalid address/ Address not supported \n");
        ht_worker_free(htt);
        return NULL;
    }

    int status;
    if ((status = connect(htt->poll.fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr))) < 0) {
        printf("\nERROR: Connection Failed : %d\n", status);
        ht_worker_free(htt);
        return NULL;
    }

    return htt;
}

bool ht_send(ht_worker* htt, const char* request) {
    // send(myc.client_fd, req, strlen(req), 0);
    ssize_t req_size = strlen(request);
    ssize_t written = write(htt->poll.fd, request, req_size);
    assert(written == req_size && "Couldnt write the whole request.");
    printf("INFO: Request Send!\n");
    htt->working = true;
    return true;
}

bool ht_poll(ht_worker* htt, int timeout) {
    htt->polled_for++;

    static char tmp[BUFF_SIZE];
    memset(tmp, 0, BUFF_SIZE);

    if (htt->waiting || htt->last_read > 0) {
        if (poll(&htt->poll, 1, timeout) > 0) {
            htt->waiting = false;
            htt->last_read = read(htt->poll.fd, tmp, BUFF_SIZE - 1);
            if (htt->last_read > 0) {
                if (htt->last_read + htt->total_read + 1 > htt->buf_size) {
                    htt->buf_size *= 2;
                    htt->buffer = (char*)realloc(htt->buffer, htt->buf_size);
                }
                memcpy(htt->buffer + htt->total_read, tmp, htt->last_read + 1);
                htt->total_read += htt->last_read;
                htt->buffer[htt->total_read] = '\0';
            }
        } else {
            // printf("Polling...\n");
            htt->last_read = 0;
        }
        return false;
    } else {
        htt->working = false;
        htt->received = true;
        return htt->received;
    }
}

ht_message* ht_get_response(ht_worker* htt) {
    assert(htt->polled_for > 0 && "This worker never worked");
    assert(htt->total_read > 0 && "This worker doesnt show his work");
    ht_sv response = ht_sv_from_buffer(htt->buffer, htt->total_read);

    HTTP_SECTION section = HT_SEC_TITLE;
    size_t total_body_len = 0;
    size_t body_written = 0;

    ht_message* h = (ht_message*)calloc(1, sizeof(ht_message));
    h->headers.capacity = 10;
    h->headers.keys = (ht_sv*)calloc(h->headers.capacity, sizeof(ht_sv));
    h->headers.vals = (ht_sv*)calloc(h->headers.capacity, sizeof(ht_sv));

    h->all = (char*)calloc(htt->total_read * 2 + 1, sizeof(char));

    while (response.count > 0 && section != HT_SEC_END) {
        ht_sv chop = ht_sv_split_once(&response, '\n');
        switch (section) {
        case HT_SEC_TITLE: {
            ht_sv ver = ht_sv_split_once(&chop, ' ');
            ht_sv code = ht_sv_split_once(&chop, ' ');
            ht_sv st = chop;

            h->version = ver;

            h->st_code = ht_sv_to_int(code, 10);

            h->st_message = st;

            section = HT_SEC_HEADER;
            break;
        }
        case HT_SEC_HEADER: {
            chop = ht_sv_trim(chop);
            if (chop.count <= 1) {
                if (h->st_code == 400) {
                    section = HT_SEC_NO_BODY;
                } else {
                    section = HT_SEC_BODY;
                }
                break;
            }
            ht_sv key = ht_sv_split_once(&chop, ':');
            ht_sv val = ht_sv_trim(chop);
            if (h->headers.count + 2 >= h->headers.capacity) {
                h->headers.capacity *= 2;
                h->headers.vals = (ht_sv*)realloc(
                    h->headers.vals, sizeof(ht_sv) * h->headers.capacity);
                h->headers.keys = (ht_sv*)realloc(
                    h->headers.keys, sizeof(ht_sv) * h->headers.capacity);
            }
            h->headers.keys[h->headers.count] = key;
            h->headers.vals[h->headers.count] = val;
            h->headers.count++;
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
            assert(total_body_len <= htt->total_read
                && "We are writing more data than we got");
            assert(chop.count == len
                && "Chop has less data than it should have");
            memcpy(h->all + body_written, chop.data, len);
            body_written += len;
            break;
        }
        case HT_SEC_NO_BODY: {
            chop = ht_sv_trim(chop);
            assert(total_body_len <= htt->total_read
                && "We are writing more data than we got");
            memcpy(h->all + body_written, chop.data, chop.count);
            body_written += chop.count;
            section = HT_SEC_END;
        }
        case HT_SEC_END:
            break;
        }
    }
    h->body = ht_sv_from_buffer(h->all, body_written);
    return h;
}

void ht_worker_clean(ht_worker* http) {
    memset(http->buffer, 0, http->buf_size);
    http->working = false;
    http->received = false;
    http->waiting = true;
    http->total_read = 0;
    http->last_read = 0;
}

void ht_free(ht_message* ht) {
    free(ht->headers.keys);
    free(ht->headers.vals);
    free(ht->all);
    free(ht);
    ht = NULL;
}

void ht_worker_free(ht_worker* htt) {
    close(htt->poll.fd);
    free(htt->buffer);
    free(htt);
    htt = NULL;
}
#endif // HT_IMPLEMENTATION
