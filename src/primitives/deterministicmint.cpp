// Copyright (c) 2018 The PIVX developers
// Copyright (c) 2018 The Tessacoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "deterministicmint.h"
#include "libzerocoin/PrivateCoin.h"
#include "tinyformat.h"

using namespace libzerocoin;

CDeterministicMint::CDeterministicMint() { SetNull(); }

CDeterministicMint::CDeterministicMint(uint8_t nVersion, const uint32_t& nCount, const uint256& hashSeed,
                                       const uint256& hashSerial, const uint256& hashPubcoin,
                                       const uint256& hashStake) {
  SetNull();
  this->nMintVersion = nVersion;
  this->nCount = nCount;
  this->hashSeed = hashSeed;
  this->hashSerial = hashSerial;
  this->hashPubcoin = hashPubcoin;
  this->hashStake = hashStake;
}

void CDeterministicMint::SetNull() {
  nMintVersion = PrivateCoin::PRIVATECOIN_VERSION;
  nCount = 0;
  hashSeed.SetNull();
  hashSerial.SetNull();
  hashStake.SetNull();
  hashPubcoin.SetNull();
  txid.SetNull();
  nHeight = 0;
  denom = CoinDenomination::ZQ_ERROR;
  isUsed = false;
}

std::string CDeterministicMint::ToString() const {
  return strprintf(
      " DeterministicMint:\n   Mint version=%d\n   count=%d\n   hashseed=%s\n   hashSerial=%s\n   hashStake=%s\n   "
      "hashPubcoin=%s\n   txid=%s\n   height=%d\n   denom=%d\n   isUsed=%d\n",
      nMintVersion, nCount, hashSeed.GetHex(), hashSerial.GetHex(), hashStake.GetHex(), hashPubcoin.GetHex(), txid.GetHex(),
      nHeight, denom, isUsed);
}
