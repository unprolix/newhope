{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE Trustworthy       #-}
{-|
  Module        : Crypto.NewHope.Internal.RNG
  Description   : Implements the CTR-DRBG standard on top of AES256.
  Copyright     : © Jeremy Bornstein 2019
  License       : Apache 2.0
  Maintainer    : jeremy@bornstein.org
  Stability     : experimental
  Portability   : portable

  CTR-DRBG == Counter mode Deterministic Random Byte Generator.
  In addition, there are a few useful extras.

  Please see https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf
  for details on the standard.

  This module contains the actual implementation. Exposed definitions
  are in the 'Crypto.NewHope.RNG' module.

-}

module Crypto.NewHope.Internal.RNG where


import           Codec.Crypto.AES
import           Control.DeepSeq
import           Data.Bits
import qualified Data.ByteString         as BS
import qualified Data.ByteString.Builder as Builder
import qualified Data.ByteString.Char8   as BSC
import qualified Data.ByteString.Lazy    as BSL
import           Data.Semigroup          ((<>))
import           Data.Word


newtype RandomSeed = RandomSeed BS.ByteString

randomSeedBytes :: Int
randomSeedBytes = 48

getRandomSeedData :: RandomSeed -> BS.ByteString
getRandomSeedData (RandomSeed rsData) = rsData


-- | Strings or ByteStrings may be used for source data.
class RandomSeedable a
  where
    -- | Uses external entropy (precisely 48 bytes) to create a 'RandomSeed', used for initializing the pseudorandom number generator
    makeRandomSeed :: a -> RandomSeed

instance RandomSeedable String
  where
    makeRandomSeed s | not lengthOK = error $ "Invalid length for RandomSeed. Have " ++ show len ++ " and require " ++ show randomSeedBytes ++ " bytes."
                     | otherwise    = RandomSeed $ BSC.pack s
      where
        len = Prelude.length s
        lengthOK = len == randomSeedBytes

instance RandomSeedable BS.ByteString
  where
    makeRandomSeed bs | not lengthOK = error $ "Invalid length for RandomSeed. Have " ++ show len ++ " and require " ++ show randomSeedBytes ++ " bytes."
                      | otherwise    = RandomSeed bs
      where
        len = BS.length bs
        lengthOK = len == randomSeedBytes


-- * Key

newtype Key = Key { getKey :: BS.ByteString } deriving (Eq)

keyBytes :: Int
keyBytes = 32 -- 32 * 8 == 64 * 4 == 128 * 2 == 256 bits

createKey :: BS.ByteString -> Key
createKey value
  | BS.length value /= keyBytes = error "Incorrect key length"
  | otherwise = Key { getKey = value }

-- | We need this instance so that we can deepseq this data while doing performance tests.
instance NFData Key
  where
    rnf (Key bs) = rnf bs


-- * V

newtype V = V { getV :: BS.ByteString } deriving (Eq)

-- | The size of a V in bytes
vBytes :: Int
vBytes = 16 -- 16 * 8 == 32 * 4 == 64 * 2 == 128 bits

-- | Construct a V
createV :: BS.ByteString -> V
createV value
  | BS.length value /= vBytes = error $ "Incorrect V length: " ++ show (BS.length value)
  | otherwise = V { getV = value }


-- | Increment the V
incrementV :: V -> V
incrementV (V v) = let v' = reverse $ BS.unpack v
                       v'' = go v'
                       v''' = BS.pack $ reverse v''

                       go []          = []
                       go (0xff : is) = 0 : go is
                       go (i : is)    = (i + 1) : is
                   in V v'''

-- | We need this instance so that we can deepseq this data while doing performance tests.
instance NFData V
  where
    rnf (V bs) = rnf bs


-----------------------

-- | State for pseudorandom number generation
data Context = Context { ctxKey           :: Key
                       , ctxV             :: V
                       , ctxReseedCounter :: Int
                       } deriving (Eq)

-- | We need this instance so that we can deepseq this data while doing performance tests.
instance NFData Context
  where
    rnf Context { ctxKey = key, ctxV = v } = rnf key `seq` rnf v


-- | Update the context with new data
update :: Context -> Maybe BS.ByteString -> Context
update ctx providedData = let
    _ = ctxReseedCounter ctx
    Key key = ctxKey ctx
    v = ctxV ctx

    ecbModeDoesNotUseIV = BS.pack $ replicate 16 0

    (_, chunks) = foldr go (v, []) [0 .. (2 :: Int)]
      where
        go _ (_v, _chunks) = (v', encrypted : _chunks)
          where
            v' = incrementV _v
            encrypted = crypt' ECB key ecbModeDoesNotUseIV Encrypt (getV v')

    chunks' = reverse chunks
    unified = mconcat chunks'
    unified' = case providedData of
      Nothing            -> unified
      Just providedData' -> BS.pack $ BS.zipWith xor unified providedData'

    (nextKeyData, nextVData) = BSC.splitAt 32 unified'
    nextKey = createKey nextKeyData
    nextV = createV nextVData
    ctx' = ctx { ctxKey = nextKey, ctxV = nextV }
  in ctx'



-- * Higher-level functions using Context data

-- | Creates a 'Context' as state for the pseudorandom number generator, required for key exchange operations
randomBytesInit :: RandomSeed       -- ^ External entropy to seed the generator
                -> Maybe RandomSeed -- ^ Optional additional entropy to include
                -> Integer          -- ^ Security strength: unused by this implementation
                -> Context          -- ^ The resulting PRNG state
randomBytesInit seed personalization _securityStrength = update ctx (Just seedMaterial)
  where
    RandomSeed entropyInput = seed
    seedMaterial = BS.pack $ case personalization of
                               Nothing                    -> BS.unpack entropyInput
                               Just (RandomSeed persData) -> zipWith xor (BS.unpack entropyInput) (BS.unpack persData)
    -- initial version with dummy data; it gets immediatlely replaced with the update.
    ctx = Context { ctxKey = createKey $ BS.pack $ replicate keyBytes 0
                                , ctxV = createV $ BS.pack $ replicate vBytes 0
                                , ctxReseedCounter = 1
                                }


-- | Generate pseudorandom bytes from the Context.
randomBytes :: Context -> Int -> (BS.ByteString, Context)
randomBytes ctx count = (result, ctx'')
  where
    result = BS.take count $ BSL.toStrict $ Builder.toLazyByteString results  -- last block could be partial
    blocks = ceiling $ (fromIntegral count :: Double) / 16
    counter = ctxReseedCounter ctx + 1
    key = getKey $ ctxKey ctx
    ecbModeDoesNotUseIV = BS.pack $ replicate 16 0
    ctx'' = update ctx' { ctxReseedCounter = counter } Nothing
    (results, ctx') = foldr go (Builder.byteString BS.empty, ctx) [1 .. blocks :: Int]
      where
        go _ (_results, _ctx) = (_results <> Builder.byteString block, _ctx')
          where
            v     = incrementV $ ctxV _ctx
            block = crypt' ECB key ecbModeDoesNotUseIV Encrypt (getV v)
            _ctx' = _ctx { ctxV = v }



-- * Useful extras

-- | Computes a random Word64 along with the next context to use.  If
-- you want a full-range Word64 value, this is what you want.  If you
-- want a pretty evenly-distributed random number in a given range,
-- see randomInteger below.
nextWord64 :: Context -> (Word64, Context)
nextWord64 ctx = (value, ctx')
  where
    (fourBytes, ctx') = randomBytes ctx 4
    fourBytes'        = BS.unpack fourBytes
    value             = shiftL (fromIntegral (fourBytes' !! 0)) 24
                    .|. shiftL (fromIntegral (fourBytes' !! 1)) 16
                    .|. shiftL (fromIntegral (fourBytes' !! 2))  8
                    .|.         fromIntegral (fourBytes' !! 3)


-- | Computes a random Integer in the given range, along with the next
-- context to use.  This function body is derived from and very
-- similar to randomIvalInteger as defined in System.Random (© 2001
-- The University of Glasgow). Since this is a public domain algorithm
-- and a purely functional expression thereof, I don't think that the
-- below causes the licensing terms of the foregoing to need
-- incorporation here, but I welcome correction.
randomInteger :: Context -> (Integer, Integer) -> (Integer, Context)
randomInteger ctx (minValue, maxValue)
    | minValue > maxValue     = randomInteger ctx (maxValue, minValue)
    | otherwise = (fromInteger (minValue + v `mod` k), ctx')
  where
    (v, ctx')      = accumulate 1 0 ctx
    (genlo, genhi) = (minBound, maxBound) :: (Word64, Word64)
    b              = fromIntegral genhi - fromIntegral genlo + 1
    q              = 1000
    k              = maxValue - minValue + 1
    magtgt         = k * q

    accumulate mag vv ctx0
        | mag >= magtgt = (vv, ctx0)
        | otherwise     = v' `seq` accumulate (mag * b) v' ctx0'
      where
        (x, ctx0') = nextWord64 ctx0
        v'         = vv * b + (fromIntegral x - fromIntegral genlo)
