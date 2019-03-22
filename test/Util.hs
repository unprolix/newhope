{-# LANGUAGE Safe #-}
{-|
  Module        : Util
  Description   : Testing utility
  Copyright     : © Jeremy Bornstein 2019
  License       : Apache 2.0
  Maintainer    : jeremy@bornstein.org
  Stability     : experimental
  Portability   : portable

-}

module Util where

import           Data.Bits
import qualified Data.ByteString as BS
import           Data.Set
import           Data.Word

import qualified Crypto.NewHope.Internal.RNG as RNG

mutateOneBit :: RNG.Context -> BS.ByteString -> (BS.ByteString, RNG.Context)
mutateOneBit ctx input = (output, ctx')
  where
    (offset, ctx') = RNG.randomInteger ctx (0, fromIntegral $ BS.length input - 1)
    (bitNum, _ctx'') = RNG.randomInteger ctx' (0, 7)
    shiftedBit = shiftL (0x01 :: Word8) (fromIntegral bitNum)
    (part1, part2) = BS.splitAt (fromIntegral offset) input
    (part2a, part2b) = BS.splitAt 1 part2
    part2a' = BS.pack [xor (BS.index part2a 0) shiftedBit]
    output = BS.concat [part1, part2a', part2b]


mutateBits :: RNG.Context -> Int -> BS.ByteString -> (BS.ByteString, RNG.Context)
mutateBits ctx n input = (output, ctx')
  where
    bitCount = BS.length input * 8
    (bitsToMutate, ctx') = randomSetOfSize ctx bitCount n
    output = Prelude.foldr go input bitsToMutate
      where
        go index bs = BS.concat [part1, part2a', part2b]
          where
            offset = index `div` 8
            shiftedBit = shiftL (0x01 :: Word8) (index `mod` 8)
            (part1, part2) = BS.splitAt (fromIntegral offset) bs
            (part2a, part2b) = BS.splitAt 1 part2
            part2a' = BS.pack [xor (BS.index part2a 0) shiftedBit]


-- | A nonrepeating set of 大きさ (or n, whichever is smaller) random
-- integers from 0 to n.
randomSetOfSize :: RNG.Context -> Int -> Int -> (Set Int, RNG.Context)
randomSetOfSize ctx n 大きさ = go ctx empty
  where
    大きさ' = min n 大きさ
    go ctx_ prevResult
        | length prevResult == 大きさ' = (prevResult, ctx_)
        | otherwise                    = go ctx_' nextResult
      where
        (choice, ctx_') = RNG.randomInteger ctx_ (0, fromIntegral n - 1)
        nextResult = insert (fromIntegral choice) prevResult
