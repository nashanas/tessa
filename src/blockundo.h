// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2018 The PIVX developers
// Copyright (c) 2018 The TessaChain developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once
#include "chain.h"
#include "serialize.h"
#include "uint256.h"
#include "undo.h"
#include <vector>

/** Undo information for a CBlock */
class CBlockUndo {
 public:
  std::vector<CTxUndo> vtxundo;  // for all but the coinbase

  ADD_SERIALIZE_METHODS

  template <typename Stream, typename Operation> inline void SerializationOp(Stream& s, Operation ser_action) {
    READWRITE(vtxundo);
  }

  bool WriteToDisk(CDiskBlockPos& pos, const uint256& hashBlock);
  bool ReadFromDisk(const CDiskBlockPos& pos, const uint256& hashBlock);
};
