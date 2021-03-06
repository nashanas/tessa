#pragma once
#include "ecdsa/pubkey.h"
#include "serialize.h"

/** A key pool entry */
class CKeyPool {
 public:
  int64_t nTime;
  ecdsa::CPubKey vchPubKey;

  CKeyPool();
  CKeyPool(const ecdsa::CPubKey& vchPubKeyIn);

  ADD_SERIALIZE_METHODS

  template <typename Stream, typename Operation> inline void SerializationOp(Stream& s, Operation ser_action) {
    int nTyp = s.GetType();
    int nVersion = s.GetVersion();
    if (!(nTyp & SER_GETHASH)) READWRITE(nVersion);
    READWRITE(nTime);
    READWRITE(vchPubKey);
  }
};
