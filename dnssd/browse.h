#include <avahi-client/lookup.h>
#include <avahi-common/error.h>
#include <avahi-common/malloc.h>
#include <avahi-common/simple-watch.h>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <curl/curl.h>
#include <string>
#include <array>
#include "logger.hpp"
#define TAG "DNSBrowse"

static AvahiSimplePoll *simple_poll;

static void resolve_callback(
    AvahiServiceResolver *r,
    AVAHI_GCC_UNUSED AvahiIfIndex interface,
    AVAHI_GCC_UNUSED AvahiProtocol protocol,
    AvahiResolverEvent event,
    const char *name,
    const char *type,
    const char *domain,
    const char *host_name,
    const AvahiAddress *address,
    uint16_t port,
    AvahiStringList *txt,
    AvahiLookupResultFlags flags,
    AVAHI_GCC_UNUSED void* userdata) {
    assert(r);
    std::array<uint8_t, 6> *deviceId = (std::array<uint8_t, 6> *)userdata;
    /* Called whenever a service has been resolved successfully or timed out */
    switch (event) {
        case AVAHI_RESOLVER_FAILURE:
            LOG_ERROR("(Resolver) Failed to resolve service '{}' of type '{}' in domain '{}': {}", name, type, domain, avahi_strerror(avahi_client_errno(avahi_service_resolver_get_client(r))));
            break;
        case AVAHI_RESOLVER_FOUND: {
            char a[AVAHI_ADDRESS_STR_MAX], *t;
            LOG_DEBUG("Service '{}' of type '{}' in domain '{}':", name, type, domain);
            avahi_address_snprint(a, sizeof(a), address);
            t = avahi_string_list_to_string(txt);
            LOG_DEBUG("\t{}:{} ({})\n"
                    "\tTXT={}\n"
                    "\tcookie is {}\n"
                    "\tis_local: {}\n"
                    "\tour_own: {}\n"
                    "\twide_area: {}\n"
                    "\tmulticast: {}\n"
                    "\tcached: {}",
                    host_name, port, a,
                    t,
                    avahi_string_list_get_service_cookie(txt),
                    !!(flags & AVAHI_LOOKUP_RESULT_LOCAL),
                    !!(flags & AVAHI_LOOKUP_RESULT_OUR_OWN),
                    !!(flags & AVAHI_LOOKUP_RESULT_WIDE_AREA),
                    !!(flags & AVAHI_LOOKUP_RESULT_MULTICAST),
                    !!(flags & AVAHI_LOOKUP_RESULT_CACHED));
            avahi_free(t);
            CURL * curl;
            CURLcode res;
            LOG_INFO("Sending connection request: {}", name);
            curl = curl_easy_init();
            std::string url = "http://";
            url.append(host_name);
            url.append(":");
            url.append(std::to_string(port));
            url.append("/ctrl-int/1/connect");
            struct curl_slist *slist = NULL;
            slist = curl_slist_append(slist, "User-Agent: AirPlay/320.1");
            char id[18];
            int j = 0;
            for (int i=0; i<deviceId->size(); i++) {
              sprintf(&id[j++], "%02X", deviceId->data()[i]);
              j++;
              if(i == 5) id[j++] = '\0';
            }
            uint64_t hw = std::stoll(id, 0, 16);
            LOG_DEBUG("deviceId - 64bit: {} str: {}", hw, id);
            std::string header = "AirPlay-Receiver-Device-ID: ";
            header.append(std::to_string(hw));
            slist = curl_slist_append(slist, header.c_str());
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);
            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            res = curl_easy_perform(curl);
            LOG_DEBUG("curl res: {}", curl_easy_strerror(res));
            curl_easy_cleanup(curl);
        }
    }
    avahi_service_resolver_free(r);
}
static void browse_callback(
    AvahiServiceBrowser *b,
    AvahiIfIndex interface,
    AvahiProtocol protocol,
    AvahiBrowserEvent event,
    const char *name,
    const char *type,
    const char *domain,
    AVAHI_GCC_UNUSED AvahiLookupResultFlags flags,
    void* userdata) {
    AvahiClient *c = avahi_service_browser_get_client(b);
    std::array<uint8_t, 6> *deviceId = static_cast<std::array<uint8_t, 6> *>(userdata);
    assert(b);
    /* Called whenever a new services becomes available on the LAN or is removed from the LAN */
    switch (event) {
        case AVAHI_BROWSER_FAILURE:
            LOG_ERROR("(Browser) {}", avahi_strerror(avahi_client_errno(c)));
            avahi_simple_poll_quit(simple_poll);
            return;
        case AVAHI_BROWSER_NEW:
            LOG_INFO("(Browser) NEW: service '{}' of type '{}' in domain '{}'", name, type, domain);
            if (!(avahi_service_resolver_new(c, interface, protocol, name, type, domain, AVAHI_PROTO_UNSPEC, AVAHI_LOOKUP_USE_MULTICAST, resolve_callback, deviceId)))
                LOG_ERROR("Failed to resolve service '{}': {}", name, avahi_strerror(avahi_client_errno(c)));
            break;
        case AVAHI_BROWSER_REMOVE:
            LOG_INFO("(Browser) REMOVE: service '{}' of type '{}' in domain '{}'", name, type, domain);
            break;
        case AVAHI_BROWSER_ALL_FOR_NOW:
        case AVAHI_BROWSER_CACHE_EXHAUSTED:
            LOG_INFO("(Browser) {}", event == AVAHI_BROWSER_CACHE_EXHAUSTED ? "CACHE_EXHAUSTED" : "ALL_FOR_NOW");
            break;
    }
}


static void client_callback(AvahiClient *c, AvahiClientState state, AVAHI_GCC_UNUSED void * userdata) {
    assert(c);
    /* Called whenever the client or server state changes */
    if (state == AVAHI_CLIENT_FAILURE) {
        fprintf(stderr, "Server connection failure: %s\n", avahi_strerror(avahi_client_errno(c)));
        avahi_simple_poll_quit(simple_poll);
    }
}

static void* dns_browse_thread(void* arg) {
    curl_global_init(CURL_GLOBAL_NOTHING);
    std::array<uint8_t, 6> *deviceId = ( std::array<uint8_t, 6> *)arg;
	AvahiClient *client = NULL;
	AvahiServiceBrowser *sb = NULL;
    int error;
    int ret = 1;
    /* Allocate main loop object */
    if (!(simple_poll = avahi_simple_poll_new())) {
        fprintf(stderr, "Failed to create simple poll object.\n");
        goto fail;
    }
    /* Allocate a new client */
    client = avahi_client_new(avahi_simple_poll_get(simple_poll), AVAHI_CLIENT_NO_FAIL, client_callback, NULL, &error);
    /* Check wether creating the client object succeeded */
    if (!client) {
        fprintf(stderr, "Failed to create client: %s\n", avahi_strerror(error));
        goto fail;
    }
    /* Create the service browser */
    if (!(sb = avahi_service_browser_new(client, AVAHI_IF_UNSPEC, AVAHI_PROTO_INET6, "_carplay-ctrl._tcp", NULL, AVAHI_LOOKUP_USE_MULTICAST, browse_callback, deviceId))) {
        fprintf(stderr, "Failed to create service browser: %s\n", avahi_strerror(avahi_client_errno(client)));
        goto fail;
    }
    /* Run the main loop */
    avahi_simple_poll_loop(simple_poll);
    ret = 0;
fail:
    /* Cleanup things */
    if (sb)
        avahi_service_browser_free(sb);
    if (client)
        avahi_client_free(client);
    if (simple_poll)
        avahi_simple_poll_free(simple_poll);
    return nullptr;
}