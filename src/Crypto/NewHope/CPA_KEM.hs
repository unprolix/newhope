{-# LANGUAGE Safe #-}
{-|
  Module        : Crypto.NewHope.CPA_KEM
  Description   : IND-CPA-secure operations for the NewHope key exchange protocol
  Copyright     : © Jeremy Bornstein 2019
  License       : Apache 2.0
  Maintainer    : jeremy@bornstein.org
  Stability     : experimental
  Portability   : portable

  IND-CPA-secure operations for the NewHope key exchange protocol. The
  algorithm name is either NewHope512-CPAKEM or NewHope1024-CPAKEM,
  depending on the value of 'N'.

  This module contains the public interface. Implementation definitions
  are in the "Crypto.NewHope.Internal.CPA_KEM" module.

  * Sample usage

  @
    -- Alice initiates the exchange
    seedA                = makeRandomSeed fortyEightBytesOfEntropyA -- Seed the pseudorandom number generator (Alice's side)
    ctxA                 = randomBytesInit seedA Nothing 256        -- Source of pseudorandomness
    (pk, skA, ctxA')     = keypair ctxA N1024                       -- Alice generates a public key and her secret key

    -- [Alice sends the public key to Bob]

    -- Bob uses the public key to derive the shared secret along with data to send to Alice
    seedB                = makeRandomSeed fortyEightBytesOfEntropyB -- Seed the pseudorandom number generator (Bob's side)
    ctxB                 = randomBytesInit seedB Nothing 256        -- Source of pseudorandomness
    (sendb, keyB, ctxB') = encrypt ctxB pk                          -- Bob derives a secret key and creates a response

    -- [Bob sends sendb back to Alice]

    keyA                 = decrypt sendb skA                        -- Alice derives her copy of the shared secret
  @

-}

module Crypto.NewHope.CPA_KEM ( keypair
                              , encrypt
                              , decrypt
                              ) where

import Crypto.NewHope.Internal.CPA_KEM
