{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE Safe              #-}
{-|
  Module        : Crypto.NewHope.Internals
  Description   : Internal constants and functions
  Copyright     : © Jeremy Bornstein 2019
  License       : Apache 2.0
  Maintainer    : jeremy@bornstein.org
  Stability     : experimental
  Portability   : portable

  Internal constants and functions

-}

module Crypto.NewHope.Internals where

import           Control.DeepSeq
import qualified Data.ByteString       as BS
import qualified Data.ByteString.Char8 as BSC


-- | There are two legal parameter sets for NewHope: either 512 or 1024.
data N = N512   -- ^ Represents the N=512 parameter set
       | N1024  -- ^ Represents the N=1024 parameter set
   deriving (Eq)

-- | The numerical value of the parameter set in question
value :: N -> Int
value N512  = 512
value N1024 = 1024


q :: Int
q = 12289


-- | The size of shared key, seeds/coins, and hashes
symBytes :: Int
symBytes = 32

-- | The size of a Seed
seedBytes :: Int
seedBytes = symBytes

-- | The size of SharedSecrets
sharedSecretBytes :: Int
sharedSecretBytes = symBytes


-- | Data used throughout the NewHope implementation. Externally, used
-- to initialize the SeedExpander pseudorandom number generator.
newtype Seed = Seed BS.ByteString deriving Eq

-- | We need this instance so that we can deepseq this data for performance tests.
instance NFData Seed
  where
    rnf (Seed bs) = rnf bs


-- | Extract data from the Seed
getSeedData :: Seed -> BS.ByteString
getSeedData (Seed seedData) = seedData


-- | Seeds may be constructed using Strings or ByteStrings as source data.
class Seedable a
  where
    -- | Uses external entropy (precisely 32 bytes) to create a 'Seed'.
    makeSeed :: a -> Seed

instance Seedable BS.ByteString
  where
    makeSeed bs | not lengthOK = error $ "Invalid length for Seed. Have " ++ show len ++ " and require " ++ show symBytes ++ " bytes."
                | otherwise    = Seed bs
      where
        len      = BS.length bs
        lengthOK = len == symBytes

instance Seedable String
  where
    makeSeed s | not lengthOK = error $ "Invalid length for Seed. Have " ++ show len ++ " and require " ++ show symBytes ++ " bytes."
               | otherwise    = Seed $ BSC.pack s
      where
        len      = length s
        lengthOK = len == symBytes
