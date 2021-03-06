// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2018 The PIVX developers
// Copyright (c) 2018 The TessaChain developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#pragma once
#include "serialize.h"
#include <cstdint>

class CBlockFileInfo {
 public:
  unsigned int nBlocks;       //! number of blocks stored in file
  unsigned int nSize;         //! number of used bytes of block file
  unsigned int nUndoSize;     //! number of used bytes in the undo file
  unsigned int nHeightFirst;  //! lowest height of block in file
  unsigned int nHeightLast;   //! highest height of block in file
  uint64_t nTimeFirst;        //! earliest time of block in file
  uint64_t nTimeLast;         //! latest time of block in file

  ADD_SERIALIZE_METHODS

  template <typename Stream, typename Operation> inline void SerializationOp(Stream& s, Operation ser_action) {
    READWRITE(VARINT(nBlocks));
    READWRITE(VARINT(nSize));
    READWRITE(VARINT(nUndoSize));
    READWRITE(VARINT(nHeightFirst));
    READWRITE(VARINT(nHeightLast));
    READWRITE(VARINT(nTimeFirst));
    READWRITE(VARINT(nTimeLast));
  }

  void SetNull() {
    nBlocks = 0;
    nSize = 0;
    nUndoSize = 0;
    nHeightFirst = 0;
    nHeightLast = 0;
    nTimeFirst = 0;
    nTimeLast = 0;
  }

  CBlockFileInfo() { SetNull(); }

  std::string ToString() const;

  /** update statistics (does not update nSize) */
  void AddBlock(unsigned int nHeightIn, uint64_t nTimeIn) {
    if (nBlocks == 0 || nHeightFirst > nHeightIn) nHeightFirst = nHeightIn;
    if (nBlocks == 0 || nTimeFirst > nTimeIn) nTimeFirst = nTimeIn;
    nBlocks++;
    if (nHeightIn > nHeightLast) nHeightLast = nHeightIn;
    if (nTimeIn > nTimeLast) nTimeLast = nTimeIn;
  }
};
