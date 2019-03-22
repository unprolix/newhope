{-# LANGUAGE Safe #-}
{-|
  Module        : Crypto.NewHope.Reduce
  Description   : Montgomery reduction for use in polynomial multiplication.
  Copyright     : © Jeremy Bornstein 2019
  License       : Apache 2.0
  Maintainer    : jeremy@bornstein.org
  Stability     : experimental
  Portability   : portable

  See https://en.wikipedia.org/wiki/Montgomery_modular_multiplication

-}

module Crypto.NewHope.Reduce (montgomeryReduce) where

import Data.Bits
import Data.ByteString.Builder (toLazyByteString, word32BE)
import Data.ByteString.Lazy    (unpack)
import Data.Word

import qualified Crypto.NewHope.Internals as Internals (q)

qinv :: Word32
qinv = 12287  -- inverse_mod(p,2^18)


rlog :: Int
rlog = 18

-- low 16 bits, bigendianly, of a 32 bit word
low16 :: Word32 -> Word16
low16 n = shiftL hb 8 + lb where
  bytes = drop 2 $ unpack $ toLazyByteString $ word32BE n
  hb = fromIntegral (bytes !! 0)
  lb = fromIntegral (bytes !! 1)


montgomeryReduce :: Word32 -> Word16
montgomeryReduce a = low16 result
  where
    u      = a * qinv
    u'     = u .&. (shiftL 1 rlog - 1 )
    u''    = u' * fromIntegral Internals.q
    a'     = a + u''
    result = shiftR a' rlog
