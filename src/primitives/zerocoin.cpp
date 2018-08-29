// Copyright (c) 2017-2018 The PIVX developers
// Copyright (c) 2018 The Tessacoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/zerocoin.h"
#include "hash.h"
#include "util.h"
#include "utilstrencodings.h"
#include "streams.h"

bool CMintMeta::operator<(const CMintMeta& a) const { return this->hashPubcoin < a.hashPubcoin; }

uint256 GetSerialHash(const CBigNum& bnSerial) {
  CDataStream ss(SER_GETHASH);
  ss << bnSerial;
  return Hash(ss.begin(), ss.end());
}

uint256 GetPubCoinHash(const CBigNum& bnValue) {
  CDataStream ss(SER_GETHASH);
  ss << bnValue;
  return Hash(ss.begin(), ss.end());
}

bool CZerocoinMint::GetKeyPair(ecdsa::CKey& key) const {
  if (privkey.empty()) return error("%s: empty privkey %s", __func__, privkey.data());
  return key.SetPrivKey(privkey, true);
}

std::string CZerocoinMint::ToString() const {
  std::string str = strprintf(
      "\n  ZerocoinMint:\n   version=%d   \ntxfrom=%s   \nheight=%d \n   randomness: %s   \n serial %s   \n privkey "
      "%s\n",
      nMintVersion, txid.GetHex(), nHeight, randomness.GetHex(), serialNumber.GetHex(), HexStr(privkey));
  return str;
}

void CZerocoinSpendReceipt::AddSpend(const CZerocoinSpend& spend) { vSpends.emplace_back(spend); }

std::vector<CZerocoinSpend> CZerocoinSpendReceipt::GetSpends() { return vSpends; }

void CZerocoinSpendReceipt::SetStatus(std::string strStatus, int nStatus, int nNeededSpends) {
  strStatusMessage = strStatus;
  this->nStatus = nStatus;
  this->nNeededSpends = nNeededSpends;
}

std::string CZerocoinSpendReceipt::GetStatusMessage() { return strStatusMessage; }

int CZerocoinSpendReceipt::GetStatus() { return nStatus; }

int CZerocoinSpendReceipt::GetNeededSpends() { return nNeededSpends; }
