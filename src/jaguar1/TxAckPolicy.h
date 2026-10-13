#pragma once

#include <cstddef>
#include <cstdint>
#include "ieee80211_radiotap.h"

namespace devourer {
// Preserve monitor injection's historical no-ACK default when TX_FLAGS is
// absent. Explicit flags opt unicast frames into ACK/retry; group receivers
// and incomplete receiver addresses can never request an ACK.
inline bool jaguar1_tx_no_ack(bool has_tx_flags, uint16_t tx_flags,
                             const uint8_t* frame, size_t size) {
  return !has_tx_flags || (tx_flags & IEEE80211_RADIOTAP_F_TX_NOACK) ||
         size < 10 || (frame[4] & 1);
}
}  // namespace devourer
