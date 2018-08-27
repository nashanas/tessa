// Copyright (c) 2018 The PIVX developers
// Copyright (c) 2018 The Tessacoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "zerotracker.h"
#include "accumulators.h"
#include "main.h"
#include "sync.h"
#include "txdb.h"
#include "util.h"
#include "wallet/walletdb.h"
#include "primitives/deterministicmint.h"

using namespace std;

CZeroTracker::CZeroTracker() {
  mapSerialHashes.clear();
  mapPendingSpends.clear();
  fInitialized = false;
}

CZeroTracker::~CZeroTracker() {
  mapSerialHashes.clear();
  mapPendingSpends.clear();
}

void CZeroTracker::Init() {
  // Load all CZerocoinMints and CDeterministicMints from the database
  if (!fInitialized) {
    ListMints(false, false, true);
    fInitialized = true;
  }
}

bool CZeroTracker::Archive(CMintMeta& meta) {
  if (mapSerialHashes.count(meta.hashSerial)) mapSerialHashes.at(meta.hashSerial).isArchived = true;

  CDeterministicMint dMint;
  if (!gWalletDB.ReadDeterministicMint(meta.hashPubcoin, dMint))
    return error("%s: could not find pubcoinhash %s in db", __func__, meta.hashPubcoin.GetHex());
  if (!gWalletDB.ArchiveDeterministicOrphan(dMint))
    return error("%s: failed to archive deterministic ophaned mint", __func__);

  LogPrint(TessaLog::ZERO, "%s: archived pubcoinhash %s\n", __func__, meta.hashPubcoin.GetHex());
  return true;
}

bool CZeroTracker::UnArchive(const uint256& hashPubcoin) {
  CDeterministicMint dMint;
  if (!gWalletDB.UnarchiveDeterministicMint(hashPubcoin, dMint))
    return error("%s: failed to unarchive deterministic mint", __func__);
  Add(dMint, false);

  LogPrint(TessaLog::ZERO, "%s: unarchived %s\n", __func__, hashPubcoin.GetHex());
  return true;
}

CMintMeta CZeroTracker::Get(const uint256& hashSerial) {
  if (!mapSerialHashes.count(hashSerial)) return CMintMeta();

  return mapSerialHashes.at(hashSerial);
}

CMintMeta CZeroTracker::GetMetaFromPubcoin(const uint256& hashPubcoin) {
  for (auto it : mapSerialHashes) {
    CMintMeta meta = it.second;
    if (meta.hashPubcoin == hashPubcoin) return meta;
  }

  return CMintMeta();
}

std::vector<uint256> CZeroTracker::GetSerialHashes() {
  vector<uint256> vHashes;
  for (auto it : mapSerialHashes) {
    if (it.second.isArchived) continue;

    vHashes.emplace_back(it.first);
  }

  return vHashes;
}

CAmount CZeroTracker::GetBalance(bool fConfirmedOnly, bool fUnconfirmedOnly) const {
  CAmount nTotal = 0;
  //! zerocoin specific fields
  std::map<libzerocoin::CoinDenomination, unsigned int> myZerocoinSupply;
  for (auto& denom : libzerocoin::zerocoinDenomList) { myZerocoinSupply.insert(make_pair(denom, 0)); }

  {
    // LOCK(cs_pivtracker);
    // Get Unused coins
    for (auto& it : mapSerialHashes) {
      CMintMeta meta = it.second;
      if (meta.isUsed || meta.isArchived) continue;
      bool fConfirmed = ((meta.nHeight < chainActive.Height() - Params().Zerocoin_MintRequiredConfirmations()) &&
                         !(meta.nHeight == 0));
      if (fConfirmedOnly && !fConfirmed) continue;
      if (fUnconfirmedOnly && fConfirmed) continue;

      nTotal += libzerocoin::ZerocoinDenominationToAmount(meta.denom);
      myZerocoinSupply.at(meta.denom)++;
    }
  }
  /* (Too verbose)
for (auto& denom : libzerocoin::zerocoinDenomList) {
  LogPrint(TessaLog::ZERO, "%s My coins for denomination %d pubcoin %s\n", __func__, denom,
           myZerocoinSupply.at(denom));
}

  LogPrint(TessaLog::ZERO, "Total value of coins %d\n", nTotal);
*/
  if (nTotal < 0) nTotal = 0;  // Sanity never hurts

  return nTotal;
}

CAmount CZeroTracker::GetUnconfirmedBalance() const { return GetBalance(false, true); }

std::vector<CMintMeta> CZeroTracker::GetMints(bool fConfirmedOnly) const {
  vector<CMintMeta> vMints;
  for (auto& it : mapSerialHashes) {
    CMintMeta mint = it.second;
    if (mint.isArchived || mint.isUsed) continue;
    bool fConfirmed = (mint.nHeight < chainActive.Height() - Params().Zerocoin_MintRequiredConfirmations());
    if (fConfirmedOnly && !fConfirmed) continue;
    vMints.emplace_back(mint);
  }
  return vMints;
}

// Does a mint in the tracker have this txid
bool CZeroTracker::HasMintTx(const uint256& txid) {
  for (auto it : mapSerialHashes) {
    if (it.second.txid == txid) return true;
  }

  return false;
}

bool CZeroTracker::HasPubcoin(const CBigNum& bnValue) const {
  // Check if this mint's pubcoin value belongs to our mapSerialHashes (which includes hashpubcoin values)
  uint256 hash = GetPubCoinHash(bnValue);
  return HasPubcoinHash(hash);
}

bool CZeroTracker::HasPubcoinHash(const uint256& hashPubcoin) const {
  for (auto it : mapSerialHashes) {
    CMintMeta meta = it.second;
    if (meta.hashPubcoin == hashPubcoin) return true;
  }
  return false;
}

bool CZeroTracker::HasSerial(const CBigNum& bnSerial) const {
  uint256 hash = GetSerialHash(bnSerial);
  return HasSerialHash(hash);
}

bool CZeroTracker::HasSerialHash(const uint256& hashSerial) const {
  auto it = mapSerialHashes.find(hashSerial);
  return it != mapSerialHashes.end();
}

bool CZeroTracker::UpdateState(const CMintMeta& meta) {
  CDeterministicMint dMint;
  if (!gWalletDB.ReadDeterministicMint(meta.hashPubcoin, dMint)) {
    // Check archive just in case
    if (!meta.isArchived) return error("%s: failed to read deterministic mint from database", __func__);

    // Unarchive this mint since it is being requested and updated
    if (!gWalletDB.UnarchiveDeterministicMint(meta.hashPubcoin, dMint))
      return error("%s: failed to unarchive deterministic mint from database", __func__);
  }

  dMint.SetTxHash(meta.txid);
  dMint.SetHeight(meta.nHeight);
  dMint.SetUsed(meta.isUsed);
  dMint.SetDenomination(meta.denom);

  if (!gWalletDB.WriteDeterministicMint(dMint))
    return error("%s: failed to update deterministic mint when writing to db", __func__);

  mapSerialHashes[meta.hashSerial] = meta;

  return true;
}

void CZeroTracker::Add(const CDeterministicMint& dMint, bool isNew, bool isArchived) {
  CMintMeta meta;
  meta.hashPubcoin = dMint.GetPubcoinHash();
  meta.nHeight = dMint.GetHeight();
  //  meta.nVersion = dMint.GetVersion();
  meta.txid = dMint.GetTxHash();
  meta.isUsed = dMint.IsUsed();
  meta.hashSerial = dMint.GetSerialHash();
  meta.denom = dMint.GetDenomination();
  meta.isArchived = isArchived;
  meta.isDeterministic = true;
  mapSerialHashes[meta.hashSerial] = meta;

  if (isNew) gWalletDB.WriteDeterministicMint(dMint);
}

void CZeroTracker::SetPubcoinUsed(const uint256& hashPubcoin, const uint256& txid) {
  if (!HasPubcoinHash(hashPubcoin)) return;
  CMintMeta meta = GetMetaFromPubcoin(hashPubcoin);
  meta.isUsed = true;
  mapPendingSpends.insert(make_pair(meta.hashSerial, txid));
  UpdateState(meta);
}

void CZeroTracker::SetPubcoinNotUsed(const uint256& hashPubcoin) {
  if (!HasPubcoinHash(hashPubcoin)) return;
  CMintMeta meta = GetMetaFromPubcoin(hashPubcoin);
  meta.isUsed = false;

  if (mapPendingSpends.count(meta.hashSerial)) mapPendingSpends.erase(meta.hashSerial);

  UpdateState(meta);
}

void CZeroTracker::RemovePending(const uint256& txid) {
  uint256 hashSerial;
  for (auto it : mapPendingSpends) {
    if (it.second == txid) {
      hashSerial = it.first;
      break;
    }
  }

  if (UintToArith256(hashSerial) > 0) mapPendingSpends.erase(hashSerial);
}

bool CZeroTracker::UpdateStatusInternal(const std::set<uint256>& setMempool, CMintMeta& mint) {
  //! Check whether this mint has been spent and is considered 'pending' or 'confirmed'
  // If there is not a record of the block height, then look it up and assign it
  uint256 txidMint;
  bool isMintInChain = zerocoinDB->ReadCoinMint(mint.hashPubcoin, txidMint);

  // See if there is internal record of spending this mint (note this is memory only, would reset on restart)
  bool isPendingSpend = static_cast<bool>(mapPendingSpends.count(mint.hashSerial));

  // See if there is a blockchain record of spending this mint
  uint256 txidSpend;
  bool isConfirmedSpend = zerocoinDB->ReadCoinSpend(mint.hashSerial, txidSpend);

  // Double check the mempool for pending spend
  if (isPendingSpend) {
    uint256 txidPendingSpend = mapPendingSpends.at(mint.hashSerial);
    if (!setMempool.count(txidPendingSpend) || isConfirmedSpend) {
      RemovePending(txidPendingSpend);
      isPendingSpend = false;
      LogPrint(TessaLog::ZERO, "%s : Pending txid %s removed because not in mempool\n", __func__,
               txidPendingSpend.GetHex());
    }
  }

  bool isUsed = isPendingSpend || isConfirmedSpend;

  if (!mint.nHeight || !isMintInChain || isUsed != mint.isUsed) {
    CTransaction tx;
    uint256 hashBlock;

    // Txid will be marked 0 if there is no knowledge of the final tx hash yet
    if (mint.txid.IsNull()) {
      if (!isMintInChain) {
        LogPrintf("%s : Failed to find mint in zerocoinDB %s\n", __func__, mint.hashPubcoin.GetHex().substr(0, 6));
        mint.isArchived = true;
        Archive(mint);
        return true;
      }
      mint.txid = txidMint;
    }

    if (setMempool.count(mint.txid)) return true;

    // Check the transaction associated with this mint
    if (!IsInitialBlockDownload() && !GetTransaction(mint.txid, tx, hashBlock, true)) {
      LogPrintf("%s : Failed to find tx for mint txid=%s\n", __func__, mint.txid.GetHex());
      mint.isArchived = true;
      Archive(mint);
      return true;
    }

    // An orphan tx if hashblock is in mapBlockIndex but not in chain active
    if (mapBlockIndex.count(hashBlock) && !chainActive.Contains(mapBlockIndex.at(hashBlock))) {
      LogPrintf("%s : Found orphaned mint txid=%s\n", __func__, mint.txid.GetHex());
      mint.isUsed = false;
      mint.nHeight = 0;
      if (tx.IsCoinStake()) {
        mint.isArchived = true;
        Archive(mint);
      }

      return true;
    }

    // Check that the mint has correct used status
    if (mint.isUsed != isUsed) {
      LogPrint(TessaLog::ZERO, "%s : Set mint %s isUsed to %d\n", __func__, mint.hashPubcoin.GetHex(), isUsed);
      mint.isUsed = isUsed;
      return true;
    }
  }

  return false;
}

std::set<CMintMeta> CZeroTracker::ListMints(bool fUnusedOnly, bool fMatureOnly, bool fUpdateStatus) {
  if (fUpdateStatus) {
    std::list<CDeterministicMint> listDeterministicDB = gWalletDB.ListDeterministicMints();
    for (auto& dMint : listDeterministicDB) Add(dMint);
    LogPrint(TessaLog::ZERO, "%s: added %d dzkp from DB\n", __func__, listDeterministicDB.size());
  }

  std::vector<CMintMeta> vOverWrite;
  std::set<CMintMeta> setMints;
  std::set<uint256> setMempool;
  {
    LOCK(mempool.cs);
    mempool.getTransactions(setMempool);
  }

  std::map<libzerocoin::CoinDenomination, int> mapMaturity = GetMintMaturityHeight();
  for (auto& it : mapSerialHashes) {
    CMintMeta mint = it.second;

    // This is only intended for unarchived coins
    if (mint.isArchived) continue;

    // Update the metadata of the mints if requested
    if (fUpdateStatus && UpdateStatusInternal(setMempool, mint)) {
      if (mint.isArchived) continue;

      // Mint was updated, queue for overwrite
      vOverWrite.emplace_back(mint);
    }

    if (fUnusedOnly && mint.isUsed) continue;

    if (fMatureOnly) {
      // Not confirmed
      if (!mint.nHeight || mint.nHeight > chainActive.Height() - Params().Zerocoin_MintRequiredConfirmations())
        continue;
      if (mint.nHeight >= mapMaturity.at(mint.denom)) continue;
    }
    setMints.insert(mint);
  }

  // overwrite any updates
  for (CMintMeta& meta : vOverWrite) UpdateState(meta);

  return setMints;
}

void CZeroTracker::Clear() { mapSerialHashes.clear(); }
