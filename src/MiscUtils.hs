{-# LANGUAGE Trustworthy #-}
{-|
  Module        : MiscUtils
  Description   : Miscellaneous utility
  Copyright     : © Jeremy Bornstein 2019
  License       : Apache 2.0
  Maintainer:   : jeremy@bornstein.org
  Stability     : experimental
  Portability   : portable

  I guess it can't be truly miscellaneous because there is essentially
  only one thing here. C'est la vie.

-}

module MiscUtils where

import qualified Data.ByteString     as BS
import qualified Data.Vector.Unboxed as VU


-- | Chunkable allows an ordered container of things to be chunked
-- into a list of smaller versions of that thing, each containing N of
-- them instead of the full amount. The final item may contain fewer.
-- That is to say, a list of integers can be transformed into a list
-- of lists of 8 integers each, etc.
class Chunkable a
  where
    chunk :: Int -> a -> [a]


instance VU.Unbox a => Chunkable (VU.Vector a)
  where
    chunk n v = if VU.null as
                then [a]
                else a : chunk n as
      where
        (a, as) = VU.splitAt n v


instance Chunkable BS.ByteString
  where
    chunk n bs = if BS.length bs == 0
                 then []
                 else a : chunk n as
      where
        (a, as) = BS.splitAt 2 bs


instance Chunkable [a]
  where
    chunk n list = if null as
                    then [a]
                    else a : chunk n as
      where
        (a, as) = splitAt n list
