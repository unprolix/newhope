{-# LANGUAGE Trustworthy #-}
{-|
  Module        : Crypto.NewHope.Test.Poly
  Description   : Testing code for Poly
  Copyright     : © Jeremy Bornstein 2019
  License       : Apache 2.0
  Maintainer    : jeremy@bornstein.org
  Stability     : experimental
  Portability   : portable

-}

module Crypto.NewHope.Test.Poly where


import qualified Data.ByteString       as BS
import qualified Data.ByteString.Char8 as BSC
import           Data.Map
import qualified Data.Vector.Unboxed   as VU
import           Data.Word
import           Test.Tasty
import           Test.Tasty.HUnit
import           Test.Tasty.QuickCheck as QC hiding (output)
import           Text.Trifecta


import           ConfigFile
import qualified Crypto.NewHope.Internals as Internals
import           Crypto.NewHope.Poly      (Poly (..))
import qualified Crypto.NewHope.Poly      as Poly
import           StringUtils


-- all the validation data for these tests
configFile :: IO Config
configFile = fromFile "Poly.cfg"


data MiscValidationParams = MiscValidationParams { coeffFreezePairs :: [(Word16, Word16)]
                                                 , flipabsPairs     :: [(Word16, Word16)]
                                                 } deriving Show

miscFromConfig :: Assignments -> MiscValidationParams
miscFromConfig section = MiscValidationParams { coeffFreezePairs = coeffFreezePairs', flipabsPairs = flipabsPairs' }
  where
    Text.Trifecta.Success coeffFreezePairs' = parseString parseListIntegralPairs mempty $ section ! "coeff_freeze"
    Text.Trifecta.Success flipabsPairs' = parseString parseListIntegralPairs mempty $ section ! "flipabs"

coeffFreezeCheck :: MiscValidationParams -> TestTree
coeffFreezeCheck params = testCase "coeff_freeze"
    $ assertBool "broken" allIsWell
  where
    pairs = coeffFreezePairs params
    allIsWell = go pairs
      where
        go []               = True
        go ((a, a') : rest) = (Poly.coeffFreeze a == a') || go rest

flipabsCheck :: MiscValidationParams -> TestTree
flipabsCheck params = testCase "flipabs"
    $ assertBool "broken" allIsWell
  where
    pairs = flipabsPairs params
    allIsWell = go pairs
      where
        go []               = True
        go ((a, a') : rest) = (Poly.flipabs a == a') || go rest


newtype WrapPoly = WrapPoly Poly deriving Show

instance Arbitrary WrapPoly where
  arbitrary = do
    a <- frequency [ (1, sequence [ arbitrary | _ <- [1 .. 512 :: Int]])
                   , (1, sequence [ arbitrary | _ <- [1 .. 1024 :: Int]])]
    return $ WrapPoly $ Poly (VU.fromList a)


newtype WrapPoly512 = WrapPoly512 Poly deriving Show

instance Arbitrary WrapPoly512 where
  arbitrary = do
    a <- sequence [ arbitrary | _ <- [1 .. 512 :: Int]]
    return $ WrapPoly512 $ Poly (VU.fromList a)

newtype WrapPoly1024 = WrapPoly1024 Poly deriving Show

instance Arbitrary WrapPoly1024 where
  arbitrary = do
    a <- sequence [ arbitrary | _ <- [1 .. 1024 :: Int]]
    return $ WrapPoly1024 $ Poly (VU.fromList a)


data ToBytesValidationParams = ToBytesValidationParams { toBytesInput  :: Poly
                                                       , toBytesOutput :: BS.ByteString
                                                       } deriving Show

toBytesFromConfig :: Assignments -> ToBytesValidationParams
toBytesFromConfig section = ToBytesValidationParams { toBytesInput = inputPoly
                                                    , toBytesOutput = outputBS
                                                    }
  where
    Text.Trifecta.Success input = parseString parseListWordIntegral mempty $ section ! "input"
    inputPoly = Poly $ VU.fromList input
    outputBS = hexStringToByteString $ section ! "output"


toBytesCheck :: ToBytesValidationParams -> TestTree
toBytesCheck params = testCase "poly_tobytes"
    $ assertEqual "it is" validatedResult calculatedResult
  where
    validatedResult =  toBytesOutput params
    calculatedResult = Poly.toByteString $ toBytesInput params


data FromBytesValidationParams = FromBytesValidationParams { fromBytesInput  :: BS.ByteString
                                                           , fromBytesOutput :: Poly
                                                           } deriving Show

fromBytesFromConfig :: Assignments -> FromBytesValidationParams
fromBytesFromConfig section = FromBytesValidationParams { fromBytesInput = inputBS
                                                        , fromBytesOutput = outputVector
                                                        }
  where
    inputBS = hexStringToByteString $ section ! "input"
    Text.Trifecta.Success output = parseString parseListWordIntegral mempty $ section ! "output"
    outputVector = Poly $ VU.fromList output


fromBytesCheck :: FromBytesValidationParams -> TestTree
fromBytesCheck params = testCase "fromByteString"
    $ assertEqual "it is" validatedResult calculatedResult
  where
    validatedResult =  fromBytesOutput params
    calculatedResult = Poly.fromByteString $ fromBytesInput params


-- we need an entire post-routine roundtrip because there is some sort of convergence happening
propPolynomialEncodeRoundtrip :: WrapPoly -> Bool
propPolynomialEncodeRoundtrip (WrapPoly poly) = let
    asBytes = Poly.toByteString poly
    asPoly = Poly.fromByteString asBytes
    asBytes' = Poly.toByteString asPoly
  in asBytes == asBytes'


data CompressValidationParams = CompressValidationParams { compressInput  :: Poly
                                                         , compressOutput :: BS.ByteString
                                                         } deriving Show

compressFromConfig :: Assignments -> CompressValidationParams
compressFromConfig section = CompressValidationParams { compressInput = inputPoly
                                                      , compressOutput = outputBS
                                                      }
  where
    Text.Trifecta.Success input = parseString parseListWordIntegral mempty $ section ! "input"
    inputPoly = Poly $ VU.fromList input
    outputBS = hexStringToByteString $ section ! "output"

compressCheck :: CompressValidationParams -> TestTree
compressCheck params = testCase "poly_compress"
    $ assertEqual "it is" validatedResult calculatedResult
  where
    validatedResult =  compressOutput params
    calculatedResult = Poly.compress $ compressInput params


data DecompressValidationParams = DecompressValidationParams { decompressInput  :: BS.ByteString
                                                             , decompressOutput :: Poly
                                                             } deriving Show

decompressFromConfig :: Assignments -> DecompressValidationParams
decompressFromConfig section = DecompressValidationParams { decompressInput = inputBS
                                                          , decompressOutput = outputPoly
                                                          }
  where
    inputBS = hexStringToByteString $ section ! "input"
    Text.Trifecta.Success output = parseString parseListWordIntegral mempty $ section ! "output"
    outputPoly = Poly $ VU.fromList output


decompressCheck :: DecompressValidationParams -> TestTree
decompressCheck params = testCase "poly_decompress"
    $ assertEqual "it is" validatedResult calculatedResult
  where
    validatedResult =  decompressOutput params
    calculatedResult = Poly.decompress $ decompressInput params


-- *should* this work?
propCompressionRoundtrip :: Poly -> Bool
propCompressionRoundtrip poly = let
    compressed = Poly.compress poly
    decompressed = Poly.decompress compressed
    recompressed = Poly.compress decompressed
    redecompressed = Poly.decompress recompressed
  in redecompressed == decompressed


data FromMsgValidationParams = FromMsgValidationParams { fromMsgInput  :: BS.ByteString
                                                       , fromMsgOutput :: Poly
                                                       } deriving Show

fromMsgFromConfig :: Assignments -> FromMsgValidationParams
fromMsgFromConfig section = FromMsgValidationParams { fromMsgInput = inputVector
                                                    , fromMsgOutput = outputPoly
                                                    }
  where
    inputVector = BSC.pack $ section ! "input"
    Text.Trifecta.Success output = parseString parseListWordIntegral mempty $ section ! "output"
    outputPoly = Poly $ VU.fromList output


fromMsgCheck :: FromMsgValidationParams -> TestTree
fromMsgCheck params = testCase "poly_frommsg"
    $ assertEqual "it is" validatedResult calculatedResult
  where
    validatedResult =  fromMsgOutput params
    n = Poly.getN validatedResult
    calculatedResult = Poly.fromMsg n $ fromMsgInput params

data ToMsgValidationParams = ToMsgValidationParams { toMsgInput  :: Poly
                                                   , toMsgOutput :: BS.ByteString
                                                   } deriving Show

toMsgFromConfig :: Assignments -> ToMsgValidationParams
toMsgFromConfig section = ToMsgValidationParams { toMsgInput = inputPoly
                                                , toMsgOutput = outputBS
                                                }
  where
    Text.Trifecta.Success input = parseString parseListWordIntegral mempty $ section ! "input"
    inputPoly = Poly $ VU.fromList input
    outputBS = hexStringToByteString $ section ! "output"


toMsgCheck :: ToMsgValidationParams -> TestTree
toMsgCheck params = testCase "poly_tomsg"
    $ assertEqual "it is" validatedResult calculatedResult
  where
    validatedResult =  toMsgOutput params
    calculatedResult = Poly.toMsg $ toMsgInput params

-----

data UniformValidationParams = UniformValidationParams { uniformSeed   :: Internals.Seed
                                                       , uniformOutput :: Poly
                                                       }

uniformFromConfig :: Assignments -> UniformValidationParams
uniformFromConfig section = UniformValidationParams { uniformSeed = seed
                                                    , uniformOutput = outputPoly
                                                    }
  where
    seed = Internals.makeSeed $ hexStringToByteString $ section ! "seed"
    Text.Trifecta.Success output = parseString parseListWordIntegral mempty $ section ! "output"
    outputPoly = Poly $ VU.fromList output


uniformCheck :: UniformValidationParams -> TestTree
uniformCheck params = testCase "poly_uniform"
    $ assertEqual "it is" validatedResult calculatedResult
  where
    validatedResult =  uniformOutput params
    n = Poly.getN validatedResult
    calculatedResult = Poly.uniform n $ uniformSeed params

-----

data SampleValidationParams = SampleValidationParams { sampleSeed   :: Internals.Seed
                                                     , sampleNonce  :: Word8
                                                     , sampleOutput :: Poly
                                                     }

sampleFromConfig :: Assignments -> SampleValidationParams
sampleFromConfig section = SampleValidationParams { sampleSeed = seed
                                                  , sampleNonce = nonce
                                                  , sampleOutput = outputPoly
                                                  }
  where
    seed = Internals.makeSeed $ hexStringToByteString $ section ! "seed"
    nonce = read $ section ! "nonce"
    Text.Trifecta.Success output = parseString parseListWordIntegral mempty $ section ! "output"
    outputPoly = Poly $ VU.fromList output


sampleCheck :: SampleValidationParams -> TestTree
sampleCheck params = testCase "poly_sample"
    $ assertEqual "it is" validatedResult calculatedResult
  where
    validatedResult =  sampleOutput params
    n = Poly.getN validatedResult
    calculatedResult = Poly.sample n (sampleSeed params) (sampleNonce params)


propAddIsCommutative512 :: WrapPoly512 -> WrapPoly512 -> Bool
propAddIsCommutative512 (WrapPoly512 a) (WrapPoly512 b) = ab == ba
  where
    ab = Poly.add a b
    ba = Poly.add b a

propAddIsCommutative1024 :: WrapPoly1024 -> WrapPoly1024 -> Bool
propAddIsCommutative1024 (WrapPoly1024 a) (WrapPoly1024 b) = ab == ba
  where
    ab = Poly.add a b
    ba = Poly.add b a


{-
-- this is not true, but why not?
propAddSub1024 :: WrapPoly1024 -> WrapPoly1024 -> WrapPoly1024 -> Bool
propAddSub1024 (WrapPoly1024 a) (WrapPoly1024 b) (WrapPoly1024 c) = aMinusBMinusC == aMinusQuantityBPlusC
  where
    aMinusBMinusC         = Poly.sub (Poly.sub a b) c
    aMinusQuantityBPlusC = Poly.sub a (Poly.add b c)
-}

tests :: IO TestTree
tests = do
    config <- configFile

    let sampleParams :: SampleValidationParams
        sampleParams = sampleFromConfig $ config `sectionNamed` "poly.sample"

        miscParams :: MiscValidationParams
        miscParams = miscFromConfig $ config `sectionNamed` "poly.misc"

        toBytesParams :: ToBytesValidationParams
        toBytesParams = toBytesFromConfig $ config `sectionNamed` "poly.tobytes"

        fromBytesParams :: FromBytesValidationParams
        fromBytesParams = fromBytesFromConfig $ config `sectionNamed` "poly.frombytes"

        toMsgParams :: ToMsgValidationParams
        toMsgParams = toMsgFromConfig $ config `sectionNamed` "poly.tomsg"

        fromMsgParams :: FromMsgValidationParams
        fromMsgParams = fromMsgFromConfig $ config `sectionNamed` "poly.frommsg"

        compressParams :: CompressValidationParams
        compressParams = compressFromConfig $ config `sectionNamed` "poly.compress"

        decompressParams :: DecompressValidationParams
        decompressParams = decompressFromConfig $ config `sectionNamed` "poly.decompress"

        uniformParams :: UniformValidationParams
        uniformParams = uniformFromConfig $ config `sectionNamed` "poly.uniform"


    return $ testGroup "Poly Tests" [ sampleCheck sampleParams
                                    , coeffFreezeCheck miscParams
                                    , flipabsCheck miscParams
                                    , toBytesCheck toBytesParams
                                    , fromBytesCheck fromBytesParams
                                    , compressCheck compressParams
                                    , decompressCheck decompressParams
                                    , fromMsgCheck fromMsgParams
                                    , toMsgCheck toMsgParams
                                    , uniformCheck uniformParams
                                    , QC.testProperty "round trip poly encode/decode" propPolynomialEncodeRoundtrip
                                    , QC.testProperty "add (N=512) is commutative" propAddIsCommutative512
                                    , QC.testProperty "add (N=1024) is commutative" propAddIsCommutative1024
                                    -- , QC.testProperty "round trip poly de/compress" propCompressionRoundtrip
                                    ]
