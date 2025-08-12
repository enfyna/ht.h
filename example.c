#include <stddef.h>
#include <stdio.h>

// #define HOST "localhost"
// #define PORT 4200
#define MAX_HTTP_BODY_LEN (8 * 1024 * 20)

#define HT_IMPLEMENTATION
#include "ht.h"

int main(void)
{
    ht_init();

    const char* req1 = ht_build_request(HT_GET, "/100");
    const char* req2 = ht_build_request(HT_GET, "/200");
    const char* req3 = ht_build_request(HT_GET, "/300");
    const char* req4 = ht_build_request(HT_GET, "/400");

    ht_send(req1);
    ht_send(req2);
    ht_send(req3);
    ht_send(req4);

    int sent = 4;
    int received = 0;

    while (sent > 0) {
        ht_active_events events = ht_poll(1);
        if (events.count > 0) {
            ht_Message htm = ht_message_from_fd(events.items[events.count - 1]);
            received++;

            printf("vvv htm str vvv\n");
            printf("%s %d %s\n", htm.status.version, htm.status.code, htm.status.status);
            for (int i = 0; i < htm.headers.count; i++) {
                printf("%s: %s\n", htm.headers.keys[i].data, htm.headers.vals[i].data);
            }
            printf("Body: %s\n", htm.body);
            printf("=== htm end ===\n");
        }

        if (received == sent)
            break;
    }

    ht_close_all();
    return 0;
}
