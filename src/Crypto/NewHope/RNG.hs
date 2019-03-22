{-# LANGUAGE Safe #-}
{-|
  Module        : Crypto.NewHope.RNG
  Description   : Pseudorandom number generation for NewHope
  Copyright     : © Jeremy Bornstein 2019
  License       : Apache 2.0
  Maintainer    : jeremy@bornstein.org
  Stability     : experimental
  Portability   : portable

  Pseudorandom number generation for NewHope.

  This module contains the public interface. Implementation definitions
  are in the "Crypto.NewHope.Internal.RNG" module.

-}

module Crypto.NewHope.RNG ( Context
                          , RandomSeedable
                          , makeRandomSeed
                          , randomBytesInit
                          , randomBytes
                          ) where


import Crypto.NewHope.Internal.RNG
