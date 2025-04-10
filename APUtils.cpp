#include "APUtils.hpp"
#include <algorithm>
#include <cstring>
#include <ifaddrs.h>
#include <memory>
#include <net/if.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdexcept>
#include <sys/ioctl.h>
#include <unistd.h>
#include <vector>

namespace AirPlay {
namespace Utils {

std::array<uint8_t, 6> getPrimaryMacAddress() {
  struct ifaddrs *ifaddr, *ifa;
  std::vector<std::string> possibleInterfaces;

  if (getifaddrs(&ifaddr) == -1) {
    throw std::runtime_error("getifaddrs failed");
  }

  for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr != NULL &&
        ifa->ifa_addr->sa_family == AF_INET) { // Consider only IPv4 interfaces
      possibleInterfaces.push_back(ifa->ifa_name);
    }
  }

  freeifaddrs(ifaddr);

  // Remove duplicate interface names (e.g., eth0 and eth0:1)
  std::sort(possibleInterfaces.begin(), possibleInterfaces.end());
  possibleInterfaces.erase(
      std::unique(possibleInterfaces.begin(), possibleInterfaces.end()),
      possibleInterfaces.end());

  int sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0) {
    throw std::runtime_error("Failed to create socket");
  }

  for (const auto &ifname : possibleInterfaces) {
    struct ifreq ifr;
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, ifname.c_str(), IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
      close(sock);
      return std::array<uint8_t, 6>{
          static_cast<uint8_t>(ifr.ifr_hwaddr.sa_data[0]),
          static_cast<uint8_t>(ifr.ifr_hwaddr.sa_data[1]),
          static_cast<uint8_t>(ifr.ifr_hwaddr.sa_data[2]),
          static_cast<uint8_t>(ifr.ifr_hwaddr.sa_data[3]),
          static_cast<uint8_t>(ifr.ifr_hwaddr.sa_data[4]),
          static_cast<uint8_t>(ifr.ifr_hwaddr.sa_data[5])};
    }
  }

  close(sock);
  throw std::runtime_error("Failed to get MAC address for any interface");
}
} // namespace Utils
} // namespace AirPlay