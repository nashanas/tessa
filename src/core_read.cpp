// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2015-2017 The PIVX developers
// Copyright (c) 2018 The Tessacoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "core_io.h"

#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "serialize.h"
#include "streams.h"
#include "util.h"
#include "utilsplitstring.h"
#include "utilstrencodings.h"
#include "version.h"
#include <algorithm>
#include <univalue.h>

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/replace.hpp>

using namespace boost;
using namespace boost::algorithm;
using namespace std;

CScript ParseScript(std::string s) {
  CScript result;

  static map<string, opcodetype> mapOpNames;

  if (mapOpNames.empty()) {
    for (int op = 0; op <= OP_ZEROCOINSPEND; op++) {
      // Allow OP_RESERVED to get into mapOpNames
      if (op < OP_NOP && op != OP_RESERVED) continue;

      const char* name = GetOpName((opcodetype)op);
      if (strcmp(name, "OP_UNKNOWN") == 0) continue;
      string strName(name);
      mapOpNames[strName] = (opcodetype)op;
      // Convenience: OP_ADD and just ADD are both recognized:
      replace_first(strName, "OP_", "");
      mapOpNames[strName] = (opcodetype)op;
    }
  }

  vector<string> words;
  Split(words, s, " \t\n", true);

  for (std::vector<std::string>::const_iterator w = words.begin(); w != words.end(); ++w) {
    if (w->empty()) {
      // Empty string, ignore. (boost::split given '' will return one word)

    } else if (std::all_of(w->begin(), w->end(), ::IsDigit) ||
               (w->front() == '-' && w->size() > 1 && std::all_of(w->begin() + 1, w->end(), ::IsDigit))) {
      // Number
      int64_t n = std::atoi((*w).c_str());
      result << n;
    } else if (w->substr(0, 2) == "0x" && w->size() > 2 && IsHex(std::string(w->begin() + 2, w->end()))) {
      // Raw hex data, inserted NOT pushed onto stack:
      std::vector<uint8_t> raw = ParseHex(string(w->begin() + 2, w->end()));
      result.insert(result.end(), raw.begin(), raw.end());
    } else if (w->size() >= 2 && w->front() == '\'' && w->back() == '\'') {
      // Single-quoted string, pushed as data. NOTE: this is poor-man's
      // parsing, spaces/tabs/newlines in single-quoted strings won't work.
      std::vector<uint8_t> value(w->begin() + 1, w->end() - 1);
      result << value;
    } else if (mapOpNames.count(*w)) {
      // opcode, e.g. OP_ADD or ADD:
      result << mapOpNames[*w];
    } else {
      throw runtime_error("script parse error");
    }
  }

  return result;
}

bool DecodeHexTx(CTransaction& tx, const std::string& strHexTx) {
  if (!IsHex(strHexTx)) return false;

  vector<uint8_t> txData(ParseHex(strHexTx));
  CDataStream ssData(txData, SER_NETWORK, PROTOCOL_VERSION);
  try {
    ssData >> tx;
  } catch (const std::exception&) { return false; }

  return true;
}

bool DecodeHexBlk(CBlock& block, const std::string& strHexBlk) {
  if (!IsHex(strHexBlk)) return false;

  std::vector<uint8_t> blockData(ParseHex(strHexBlk));
  CDataStream ssBlock(blockData, SER_NETWORK, PROTOCOL_VERSION);
  try {
    ssBlock >> block;
  } catch (const std::exception&) { return false; }

  return true;
}

uint256 ParseHashUV(const UniValue& v, const string& strName) {
  string strHex;
  if (v.isStr()) strHex = v.getValStr();
  return ParseHashStr(strHex, strName);  // Note: ParseHashStr("") throws a runtime_error
}

uint256 ParseHashStr(const std::string& strHex, const std::string& strName) {
  if (!IsHex(strHex))  // Note: IsHex("") is false
    throw runtime_error(strName + " must be hexadecimal string (not '" + strHex + "')");

  uint256 result;
  result.SetHex(strHex);
  return result;
}

vector<uint8_t> ParseHexUV(const UniValue& v, const string& strName) {
  string strHex;
  if (v.isStr()) strHex = v.getValStr();
  if (!IsHex(strHex)) throw runtime_error(strName + " must be hexadecimal string (not '" + strHex + "')");
  return ParseHex(strHex);
}
