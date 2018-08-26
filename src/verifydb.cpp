// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2018 The PIVX developers
// Copyright (c) 2018 The Tessacoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "verifydb.h"
#include "blockdisk.h"
#include "blockundo.h"
#include "main_externs.h"
#include "ui_interface.h"
#include "util.h"
#include "validationstate.h"

#include "init.h"
#include <boost/thread.hpp>

using namespace std;

CVerifyDB::CVerifyDB() { uiInterface.ShowProgress(_("Verifying blocks..."), 0); }

CVerifyDB::~CVerifyDB() { uiInterface.ShowProgress("", 100); }

bool CVerifyDB::VerifyDB(CCoinsView* coinsview, int nCheckLevel, int nCheckDepth) {
  LOCK(cs_main);
  if (chainActive.Tip() == nullptr || chainActive.Tip()->pprev == nullptr) return true;

  // Verify blocks in the best chain
  if (nCheckDepth <= 0) nCheckDepth = 1000000000;  // suffices until the year 19000
  if (nCheckDepth > chainActive.Height()) nCheckDepth = chainActive.Height();
  nCheckLevel = std::max(0, std::min(4, nCheckLevel));
  LogPrintf("Verifying last %i blocks at level %i\n", nCheckDepth, nCheckLevel);
  CCoinsViewCache coins(coinsview);
  CBlockIndex* pindexState = chainActive.Tip();
  CBlockIndex* pindexFailure = nullptr;
  int nGoodTransactions = 0;
  CValidationState state;
  for (CBlockIndex* pindex = chainActive.Tip(); pindex && pindex->pprev; pindex = pindex->pprev) {
    boost::this_thread::interruption_point();
    uiInterface.ShowProgress(_("Verifying blocks..."),
                             std::max(1, std::min(99, (int)(((double)(chainActive.Height() - pindex->nHeight)) /
                                                            (double)nCheckDepth * (nCheckLevel >= 4 ? 50 : 100)))));
    if (pindex->nHeight < chainActive.Height() - nCheckDepth) break;
    CBlock block;
    // check level 0: read from disk
    if (!ReadBlockFromDisk(block, pindex))
      return error("VerifyDB() : *** ReadBlockFromDisk failed at %d, hash=%s", pindex->nHeight,
                   pindex->GetBlockHash().ToString());
    // check level 1: verify block validity
    if (nCheckLevel >= 1 && !CheckBlock(block, state))
      return error("VerifyDB() : *** found bad block at %d, hash=%s\n", pindex->nHeight,
                   pindex->GetBlockHash().ToString());
    // check level 2: verify undo validity
    if (nCheckLevel >= 2 && pindex) {
      CBlockUndo undo;
      CDiskBlockPos pos = pindex->GetUndoPos();
      if (!pos.IsNull()) {
        if (!undo.ReadFromDisk(pos, pindex->pprev->GetBlockHash()))
          return error("VerifyDB() : *** found bad undo data at %d, hash=%s\n", pindex->nHeight,
                       pindex->GetBlockHash().ToString());
      }
    }
    // check level 3: check for inconsistencies during memory-only disconnect of tip blocks
    if (nCheckLevel >= 3 && pindex == pindexState &&
        (coins.GetCacheSize() + pcoinsTip->GetCacheSize()) <= nCoinCacheSize) {
      bool fClean = true;
      if (!DisconnectBlock(block, state, pindex, coins, &fClean))
        return error("VerifyDB() : *** irrecoverable inconsistency in block data at %d, hash=%s", pindex->nHeight,
                     pindex->GetBlockHash().ToString());
      pindexState = pindex->pprev;
      if (!fClean) {
        nGoodTransactions = 0;
        pindexFailure = pindex;
      } else
        nGoodTransactions += block.vtx.size();
    }
    if (ShutdownRequested()) return true;
  }
  if (pindexFailure)
    return error(
        "VerifyDB() : *** coin database inconsistencies found (last %i blocks, %i good transactions before that)\n",
        chainActive.Height() - pindexFailure->nHeight + 1, nGoodTransactions);

  // check level 4: try reconnecting blocks
  if (nCheckLevel >= 4) {
    CBlockIndex* pindex = pindexState;
    while (pindex != chainActive.Tip()) {
      boost::this_thread::interruption_point();
      uiInterface.ShowProgress(_("Verifying blocks..."),
                               std::max(1, std::min(99, 100 - (int)(((double)(chainActive.Height() - pindex->nHeight)) /
                                                                    (double)nCheckDepth * 50))));
      pindex = chainActive.Next(pindex);
      CBlock block;
      if (!ReadBlockFromDisk(block, pindex))
        return error("VerifyDB() : *** ReadBlockFromDisk failed at %d, hash=%s", pindex->nHeight,
                     pindex->GetBlockHash().ToString());
      if (!ConnectBlock(block, state, pindex, coins, false))
        return error("VerifyDB() : *** found unconnectable block at %d, hash=%s", pindex->nHeight,
                     pindex->GetBlockHash().ToString());
    }
  }

  LogPrintf("No coin database inconsistencies in last %i blocks (%i transactions)\n",
            chainActive.Height() - pindexState->nHeight, nGoodTransactions);

  return true;
}
