{-# LANGUAGE Trustworthy #-}
{-|
  Module        : Crypto.NewHope.Test.NTT
  Description   : Testing code for NTT
  Copyright     : © Jeremy Bornstein 2019
  License       : Apache 2.0
  Maintainer    : jeremy@bornstein.org
  Stability     : experimental
  Portability   : portable

-}

module Crypto.NewHope.Test.NTT where

import           Data.Map
import qualified Data.Vector.Unboxed   as VU
import           Data.Word
import           Test.Tasty
import           Test.Tasty.HUnit
import           Test.Tasty.QuickCheck as QC hiding (output)
import           Text.Trifecta

import ConfigFile
import Crypto.NewHope.NTT


-- all the validation data for these tests
configFile512 :: IO Config
configFile512 = fromFile "NTT_512.cfg"

configFile1024 :: IO Config
configFile1024 = fromFile "NTT_1024.cfg"


-- generate (arbitrary :: Gen Word16Vector512)

newtype WrappedVUUnbox a = WrappedVUUnbox (VU.Vector a) deriving Show

instance (Arbitrary a, VU.Unbox a) => Arbitrary (WrappedVUUnbox a) where
    arbitrary = fmap (WrappedVUUnbox . VU.fromList) arbitrary


newtype Word16Vector512 = Word16Vector512 (VU.Vector Word16) deriving (Eq, Show)
newtype Word16Vector1024 = Word16Vector1024 (VU.Vector Word16) deriving (Eq, Show)

instance Arbitrary Word16Vector512 where
  arbitrary = sized $ \_n -> do
      let notN = 512 :: Int
      a <- sequence [ suchThat arbitrary (< 512) | _ <- [1..notN]]
      return $ Word16Vector512 (VU.fromList a)

instance Arbitrary Word16Vector1024 where
  arbitrary = sized $ \_n -> do
      let notN = 1024 :: Int
      a <- sequence [ suchThat arbitrary (< 1024) | _ <- [1..notN]]
      return $ Word16Vector1024 (VU.fromList a)


propRev512 :: Word16Vector512 -> Bool
propRev512 v = v0 == v2 where
  Word16Vector512 v0 = v
  v1 = bitrev v0
  v2 = bitrev v1

propRev1024 :: Word16Vector1024 -> Bool
propRev1024 v = v0 == v2 where
  Word16Vector1024 v0 = v
  v1 = bitrev v0
  v2 = bitrev v1


data BitReverseValidationParams = BitReverseValidationParams { getBTKeySize :: Int
                                                             , getBTInput   :: VU.Vector Word16
                                                             , getBTOutput  :: VU.Vector Word16
                                                             } deriving Show
btFromConfig :: Config -> BitReverseValidationParams
btFromConfig config = BitReverseValidationParams { getBTKeySize = bits
                                          , getBTInput = inputVector
                                          , getBTOutput = outputVector
                                          }
  where
    section = config `sectionNamed` "bitrev"
    bits = read $ section ! "n" :: Int
    Text.Trifecta.Success input = parseString parseListWordIntegral mempty $ section ! "input"
    inputVector = VU.fromList input
    Text.Trifecta.Success output = parseString parseListWordIntegral mempty $ section ! "output"
    outputVector = VU.fromList output


isBitReverseAccurate :: BitReverseValidationParams -> Bool
isBitReverseAccurate config = expectedOutput == liveResult
  where
    expectedOutput = getBTOutput config
    input = getBTInput config
    liveResult = bitrev input


bitreverseCheck :: BitReverseValidationParams -> TestTree
bitreverseCheck params = testCase ("bitreverse (N=" ++ show n ++ ")")
    (assertEqual "it is" True $ isBitReverseAccurate params)
  where
    n = getBTKeySize params


data NTTValidationParams = NTTValidationParams { getKeySize :: Int
                                               , getInput   :: VU.Vector Word16
                                               , getΩ       :: VU.Vector Word16
                                               , getOutput  :: VU.Vector Word16
                                               } deriving Show


nttFromConfig :: Config -> NTTValidationParams
nttFromConfig config = NTTValidationParams { getKeySize = bits
                                           , getInput = inputVector
                                           , getΩ = ωVector
                                           , getOutput = outputVector
                                           }
  where
    section = config `sectionNamed` "ntt"
    bits = read $ findWithDefault "0" "n" section :: Int
    Text.Trifecta.Success input = parseString parseListWordIntegral mempty $ section ! "input"
    inputVector = VU.fromList input
    Text.Trifecta.Success ω = parseString parseListWordIntegral mempty $ section ! "omega"
    ωVector = VU.fromList ω
    Text.Trifecta.Success output = parseString parseListWordIntegral mempty $ section ! "output"
    outputVector = VU.fromList output


isNTTAccurate :: NTTValidationParams -> Bool
isNTTAccurate config = validResult == liveResult
  where
    validResult = getOutput config
    inputVector = getInput config
    ωVector = getΩ config
    liveResult = ntt inputVector ωVector

nttCheck :: NTTValidationParams -> TestTree
nttCheck params = testCase ("ntt (N=" ++ show n ++ ")")
    (assertEqual "it is" True $ isNTTAccurate params)
  where
    n = getKeySize params


-- the table entries should be symmetrical
checkTableEntry :: VU.Vector Word16 -> Integer -> Bool
checkTableEntry table n = let
    value0 = table VU.! fromIntegral n
    value1 = table VU.! fromIntegral value0
    result = value0 == value1 || value1 == fromIntegral n
  in result


-- check the full table. this should really be sufficient instead of the spot check that the other test provides, iirc
validateBitrevTable :: Int -> Bool
validateBitrevTable bits = and $ checkTableEntry (bitrevTable bits) <$> [0..511]

bitrevTable512Ok :: TestTree
bitrevTable512Ok = testCase "bitreverse table (N=512) is legit"
    (assertEqual "it is" True $ validateBitrevTable 512)

bitrevTable1024Ok :: TestTree
bitrevTable1024Ok = testCase "bitreverse table (N=1024) is legit"
    (assertEqual "it is" True $ validateBitrevTable 1024)


tests :: IO TestTree
tests = do
    config512 <- configFile512
    config1024 <- configFile1024

    let btParams512 :: BitReverseValidationParams
        btParams512 = btFromConfig config512

        nttParams512 :: NTTValidationParams
        nttParams512 = nttFromConfig config512

    let btParams1024 :: BitReverseValidationParams
        btParams1024 = btFromConfig config1024

        nttParams1024 :: NTTValidationParams
        nttParams1024 = nttFromConfig config1024

    return $ testGroup "NTT Tests" [ bitreverseCheck btParams512
                                   , bitreverseCheck btParams1024
                                   , bitrevTable512Ok
                                   , bitrevTable1024Ok
                                   , nttCheck nttParams512
                                   , nttCheck nttParams1024
                                   , QC.testProperty "round trip bitreversal (N=512)" propRev512
                                   , QC.testProperty "round trip bitreversal (N=1024)" propRev1024
                                   ]
