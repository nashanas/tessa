/**
 * @file       Params.h
 *
 * @brief      Parameter classes for Zerocoin.
 *
 * @author     Ian Miers, Christina Garman and Matthew Green
 * @date       June 2013
 *
 * @copyright  Copyright 2013 Ian Miers, Christina Garman and Matthew Green
 *  license    This project is released under the MIT license.
 **/
// Copyright (c) 2018 The PIVX developer
// Copyright (c) 2018 The TessaCoin developers
#pragma once

#include "ZerocoinDefines.h"
#include "bignum.h"

namespace libzerocoin {

class IntegerGroupParams {
 public:
  /** @brief Integer group class, default constructor
   *
   * Allocates an empty (uninitialized) set of parameters.
   **/
  IntegerGroupParams() { this->initialized = false; }

  bool initialized;

  /**
   * A generator for the group.
   */
  CBigNum g;

  /**
   * A second generator for the group.
   * Note log_g(h) and log_h(g) must
   * be unknown.
   */
  CBigNum h;

  CBigNum g1, g2, g3, g4, g5, g6, g7, g8, g9, ga, gb;

  /**
   * The modulus for the group.
   */
  CBigNum modulus;

  /**
   * The order of the group
   */
  CBigNum groupOrder;

  ADD_SERIALIZE_METHODS
  template <typename Stream, typename Operation> inline void SerializationOp(Stream& s, Operation ser_action) {
    READWRITE(initialized);
    READWRITE(g);
    READWRITE(h);
    READWRITE(modulus);
    READWRITE(groupOrder);
  }
};

}  // namespace libzerocoin
