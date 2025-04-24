#include "APUtils.hpp"
#include <algorithm>
#include <cstring>
#include <ifaddrs.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <sys/ioctl.h>
#include <unistd.h>

namespace AirPlay {
namespace Utils {

std::array<uint8_t , 6>	getPrimaryMacAddress() {
    std::array<uint8_t, 6> macOut{};
    struct ifaddrs *			iaList;
    const struct ifaddrs *		ia;

    iaList = NULL;
    getifaddrs( &iaList );

    for( ia = iaList; ia; ia = ia->ifa_next )
    {
        const struct sockaddr_ll *		sll;

        if( !( ia->ifa_flags & IFF_UP ) )			continue; // Skip inactive.
        if( ia->ifa_flags & IFF_LOOPBACK )			continue; // Skip loopback.
        if( !ia->ifa_addr )							continue; // Skip no addr.
        if( ia->ifa_addr->sa_family != AF_PACKET )	continue; // Skip non-AF_PACKET.
        sll = (const struct sockaddr_ll *) ia->ifa_addr;
        if( sll->sll_halen != 6 )					continue; // Skip wrong length.

        std::copy(sll->sll_addr, sll->sll_addr + 6, macOut.data());
        break;
    }
    if( iaList ) freeifaddrs( iaList );
    return macOut;
}
} // namespace Utils
} // namespace AirPlay