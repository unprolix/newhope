{-# LANGUAGE Safe #-}
{-|
  Module        : Crypto.NewHope
  Description   : NewHope cryptographic key-exchange protocol library
  Copyright     : © Jeremy Bornstein 2019
  License       : Apache 2.0
  Maintainer    : jeremy@bornstein.org
  Stability     : experimental
  Portability   : portable

  This is the main (and very sparse) public module for the NewHope
  cryptography library.  In order to perform useful operations, you
  will probably also wish to import "Crypto.NewHope.CPA_KEM" and/or
  "Crypto.NewHope.CCA_KEM", which each implement keypair generation,
  encryption, and decryption (see those modules for sample usage of
  these components to effect an actual key exchange). Also required
  for import will be "Crypto.NewHope.RNG" for generation of a
  'Context' for pseudorandom number generation, used in the key
  exchange protocol.

  You may also import the "Crypto.NewHope.SeedExpander" module to use
  the seedexpander functionality, which is not otherwise necessary for
  the key exchange protocol but which is provided here because it is
  part of the NIST spec and the reference library.

  Naming of exported symbols is largely consistent with that used in
  the reference implementation, and therefore strongly related to the
  specifications required by the NIST PQC project. However changes
  have been made to naming where they seem to make sense, e.g. instead
  of the function crypto_kem_enc() being defined twice, once each for
  the IND-CPA-secure and the IND-CCA-secure variants, here we define
  the function 'encrypt' as appropriate in "Crypto.NewHope.CCA_KEM"
  and also in "Crypto.NewHope.CPA_KEM". If you are familiar with the
  reference C implementation none of these changes should be
  surprising.

-}

module Crypto.NewHope ( N(N512, N1024)
                      ) where

import Crypto.NewHope.Internals (N (N1024, N512))
