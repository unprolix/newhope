{-# LANGUAGE BangPatterns      #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE Safe              #-}
{-|
  Module        : Crypto.NewHope.Verify
  Description   : Constant-time comparison and possible copying for NewHope
  Copyright     : © Jeremy Bornstein 2019
  License       : Apache 2.0
  Maintainer    : jeremy@bornstein.org
  Stability     : experimental
  Portability   : portable

  Constant time operations are important for protection against
  timing-based attacks on cryptosystems.

  We implement two versions for possible copying, one which uses
  mappend (and is valid for any Monoid) and the other which is
  ByteString-specific and does actual bit operations. The code
  currently just uses the first, but if we find a flaw with that then
  we can switch to the second.

-}

module Crypto.NewHope.Verify where

import           Data.Bits
import qualified Data.ByteString as BS
import           Data.Foldable
import           Data.Semigroup  (Semigroup, (<>))



-- We have tests which attempt to demonstrate that these functions
-- really do take constant time, but this should probably also be done
-- by examination of the Core generated, and the assembly generated
-- from that.

-- | If the passed Bool is True, return the first of the following
-- arguments. If it is False, return the second of the following
-- arguments. Execution of this function should take constant time.
constantTimeChoose :: (Monoid a, Semigroup a) => Bool -> a -> a -> a
constantTimeChoose !v !a !b = (if v then a else mempty) <> (if v' then b else mempty)
  where
    !v' = not v

-- | If the passed Bool is True, return the first of the
-- ByteStrings. If it is False, return the second of the ByteStrings.
-- Execution of this function should take constant time on the length
-- of the shortest of the two ByteStrings.
cmov :: Bool -> BS.ByteString -> BS.ByteString -> BS.ByteString
cmov t !r !x = BS.pack $ BS.zipWith go r x
  where
    operate = (if t then 0x00 else 0xFF) .|. (if not t then 0xFF else 0x00)
    go r' x' = r' `xor` ((x' `xor` r') .&. operate)


-- | In constant time, return True if the ByteStrings are equal and
-- False if they are not.
verify :: BS.ByteString -> BS.ByteString -> Bool
verify !a !b = Data.Foldable.foldl go True (BS.zip a b)
  where
    go accum (c, d) = (c == d) && accum
