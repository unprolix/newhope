{-# LANGUAGE Safe #-}
{-|
  Module        : Crypto.NewHope.SeedExpander
  Description   : Seed expander for NewHope.
  Copyright     : © Jeremy Bornstein 2019
  License       : Apache 2.0
  Maintainer    : jeremy@bornstein.org
  Stability     : experimental
  Portability   : portable

  The "seed expander" is a facility specified by NIST for generating
  pseudorandom data given a seed. It is not used in the actual NewHope
  key exchange and is provided here for completeness/isomorphism with
  the NewHope C reference library.

  This module contains the public interface. Implementation definitions
  are in the "Crypto.NewHope.Internal.SeedExpander" module.

  * Sample usage

  @
    let maxLen' = case maxLen 256 of Right value -> value
                                     Left x      -> error (show x)

    let diversifier = case createDiversifier (BSC.pack "12345678") of Right value -> value
                                                                      Left x      -> error (show x)

    let seed = (Internals.makeSeed "32 bytes of seed data go here...")

    let ctx = case seedexpanderInit seed diversifier maxLen' of Right value -> value
                                                                Left x      -> error (show x)

    let (ctx', buf) = case seedexpander ctx 16 of Right value -> value
                                                  Left x    r -> error (show x)
  @

-}

module Crypto.NewHope.SeedExpander ( RNGError
                                   -- * Preparing parameters
                                   , makeSeed
                                   , Seedable

                                   , maxLen
                                   , createDiversifier

                                     -- * Expanding a seed
                                   , seedexpanderInit
                                   , seedexpander

                                   ) where

import Crypto.NewHope.Internal.SeedExpander
import Crypto.NewHope.Internals             (Seedable, makeSeed)
