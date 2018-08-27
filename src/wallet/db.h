// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin developers
// Copyright (c) 2018 The TessaChain developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#define KEY_RES 100

#include "clientversion.h"
#include "fs.h"
#include "serialize.h"
#include "streams.h"
#include "sync.h"
#include "version.h"

#include <lmdb.h>
#include <string>

class CDB {
 protected:
  MDB_dbi dbi = 0;
  MDB_txn* activeTxn = nullptr;
  MDB_env* env = nullptr;
  bool fReadOnly;
  bool fDbEnvInit;

 public:
  CDB() {}
  ~CDB() { Close(); }
  mutable CCriticalSection cs_db;
  bool init(const fs::path& wallet_dir, const char* pszMode = "r+");
  bool open(const fs::path& wallet_dir, const char* pszMode = "r+");
  void Close();

  MDB_txn* TxnBegin();
  MDB_txn* ReadBegin();

 protected:
  template <typename K, typename T> bool Read(const K& key, T& value) {
    // Key
    CDataStream ssKey(SER_DISK, CLIENT_VERSION);
    ssKey.reserve(KEY_RES);
    ssKey << key;
    MDB_val datKey;
    datKey.mv_data = &ssKey[0];
    datKey.mv_size = ssKey.size();

    // Read
    MDB_val datValue;
    activeTxn = TxnBegin();
    int dbr = mdb_get(activeTxn, dbi, &datKey, &datValue);

    // Make sure we don't try to re-use this
    // if (dbr) activeTxn = nullptr;

    if (dbr) return false;
    // Throw if ret ! = 0!!!!

    // Unserialize value
    try {
      CDataStream ssValue((char*)datValue.mv_data, (char*)datValue.mv_data + datValue.mv_size, SER_DISK,
                          CLIENT_VERSION);
      ssValue >> value;
    } catch (const std::exception&) { return false; }
    return (dbr == 0);
  }

  template <typename K, typename T> bool Write(const K& key, const T& value, bool fOverwrite = true) {
    if (fReadOnly) assert(!"Write called on database in read-only mode");

    // Key
    CDataStream ssKey(SER_DISK, CLIENT_VERSION);
    ssKey.reserve(KEY_RES);
    ssKey << key;
    MDB_val datKey;
    datKey.mv_data = &ssKey[0];
    datKey.mv_size = ssKey.size();

    // Value
    CDataStream ssValue(SER_DISK, CLIENT_VERSION);
    ssValue.reserve(10000);
    ssValue << value;
    MDB_val datValue;
    datValue.mv_data = &ssValue[0];
    datValue.mv_size = ssValue.size();

    // Write
    activeTxn = TxnBegin();
    int ret = mdb_put(activeTxn, dbi, &datKey, &datValue, (fOverwrite ? 0 : MDB_NOOVERWRITE));
    ret |= TxnCommit();

    // Clear memory in case it was a private key
    memset(datKey.mv_data, 0, datKey.mv_size);
    memset(datValue.mv_data, 0, datValue.mv_size);
    return (ret == 0);
  }

  template <typename K> bool Erase(const K& key) {
    if (fReadOnly) assert(!"Erase called on database in read-only mode");

    // Key
    CDataStream ssKey(SER_DISK, CLIENT_VERSION);
    ssKey.reserve(KEY_RES);
    ssKey << key;
    MDB_val datKey;
    datKey.mv_data = &ssKey[0];
    datKey.mv_size = ssKey.size();

    // Erase
    activeTxn = TxnBegin();
    int ret = mdb_del(activeTxn, dbi, &datKey, 0);
    ret |= TxnCommit();
    return (ret == 0 || ret == MDB_NOTFOUND);
  }

  template <typename K> bool Exists(const K& key) {
    // Key
    CDataStream ssKey(SER_DISK, CLIENT_VERSION);
    ssKey.reserve(KEY_RES);
    ssKey << key;
    MDB_val datKey;
    datKey.mv_data = &ssKey[0];
    datKey.mv_size = ssKey.size();

    // Exists
    activeTxn = TxnBegin();
    int ret = mdb_get(activeTxn, dbi, &datKey, 0);

    // if non-zero, it doesn't exist!
    return (ret == 0);
  }

  MDB_cursor* GetCursor();
  int ReadAtCursor(MDB_cursor* pcursor, CDataStream& ssKey, CDataStream& ssValue, unsigned int fFlags = MDB_NEXT);

 public:
  bool Verify();
  bool TxnCommit();
  void TxnAbort();
  bool cursor_commit(MDB_cursor* pcursor);
  void cursor_close(MDB_cursor* pcursor);

  bool ReadVersion(int& nVersion) {
    nVersion = 0;
    return Read(std::string("version"), nVersion);
  }

  bool WriteVersion(int nVersion) { return Write(std::string("version"), nVersion); }
  bool Read(CDataStream& key, CDataStream& value);
  bool Write(CDataStream& key, CDataStream& value, bool fOverwrite = true);
  bool Exists(CDataStream& key);
  bool Erase(CDataStream& key);
};
