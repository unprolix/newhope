{-# LANGUAGE Trustworthy #-}
{-|
  Module        : AuxUtil
  Description   : Auxiliary utilities
  Copyright     : © Jeremy Bornstein 2019
  License       : Apache 2.0
  Maintainer    : jeremy@bornstein.org
  Stability     : experimental
  Portability   : portable

  Auxiliary utilities, used by testing and app code. Placed here to
  avoid duplication.

-}
module AuxUtil where

import Test.Tasty.QuickCheck (Arbitrary, arbitrary, frequency)

import qualified Crypto.NewHope as NewHope


newtype WrapN = WrapN NewHope.N

instance Show WrapN
  where
    show (WrapN NewHope.N512)  = "NewHope512"
    show (WrapN NewHope.N1024) = "NewHope1024"

-- TODO: isn't there a more elegant way to do this?
instance Arbitrary WrapN
  where
    arbitrary = do
      a <- frequency [ (1, return NewHope.N512)
                     , (1, return NewHope.N1024)
                     ]
      return $ WrapN a
