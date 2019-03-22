{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE Trustworthy           #-}
{-|
  Module        : Crypto.NewHope.Test.FIPS202
  Description   : Testing code for NewHope.FIPS202 (an implementation of Keccak/SHA-3)
  Copyright     : © Jeremy Bornstein 2019
  License       : Apache 2.0
  Maintainer    : jeremy@bornstein.org
  Stability     : experimental
  Portability   : portable

-}

module Crypto.NewHope.Test.FIPS202 where

import qualified Data.ByteString       as BS
import qualified Data.ByteString.Char8 as BSC
import qualified Data.Map              as Map
import qualified Data.Vector.Unboxed   as VU
import           Data.Word
import           Test.Tasty
import           Test.Tasty.HUnit
import           Text.Trifecta         hiding (count)

import ConfigFile
import Crypto.NewHope.FIPS202
import StringUtils


-- all the validation data for these tests
configFile :: IO Config
configFile = fromFile "FIPS202.cfg"


data StatePermuteValidationParams = StatePermuteValidationParams { keccakInput  :: VU.Vector Word64
                                                                 , keccakOutput :: VU.Vector Word64
                                                                 } deriving Show

keccakFromConfig :: Assignments -> StatePermuteValidationParams
keccakFromConfig section = StatePermuteValidationParams { keccakInput = inputVector, keccakOutput = outputVector }
  where
    Text.Trifecta.Success input  = parseString parseListWordIntegral mempty $ section Map.! "input"
    inputVector                  = VU.fromList input
    Text.Trifecta.Success output = parseString parseListWordIntegral mempty $ section Map.! "output"
    outputVector                 = VU.fromList output

keccakPermuteCheck :: StatePermuteValidationParams -> TestTree
keccakPermuteCheck params = testCase "keccakf1600_permute"
    $ assertEqual "it is" validatedResult calculatedResult
  where
    validatedResult  = keccakOutput params
    calculatedResult = keccakF1600StatePermute $ keccakInput params


data Shake128AbsorbValidationParams = Shake128AbsorbValidationParams { absorbSeed      :: BS.ByteString
                                                                         , absorbState :: [Word64]
                                                                         } deriving Show

absorbStateVector :: Shake128AbsorbValidationParams -> VU.Vector Word64
absorbStateVector params = VU.fromList $ absorbState params

absorbFromConfig :: Assignments -> Shake128AbsorbValidationParams
absorbFromConfig section = Shake128AbsorbValidationParams { absorbSeed = seed, absorbState = state }
  where
    seed                        = BSC.pack $ section Map.! "seed"
    Text.Trifecta.Success state = parseString parseListWordIntegral mempty $ section Map.! "state"

shake128AbsorbCheck :: Shake128AbsorbValidationParams -> String -> TestTree
shake128AbsorbCheck params variant = testCase ("shake128Absorb (" ++ variant ++ ")")
    $ assertEqual "it is" validatedResult calculatedResult
  where
    validatedResult  = absorbStateVector params
    calculatedResult = shake128Absorb $ absorbSeed params


data Shake128SqueezeValidationParams = Shake128SqueezeValidationParams { squeezeSeed       :: BS.ByteString
                                                                           , squeezeOutput :: BS.ByteString
                                                                           , squeezeState  :: VU.Vector Word64
                                                                           } deriving Show

squeezeFromConfig :: Assignments -> Shake128SqueezeValidationParams
squeezeFromConfig section = Shake128SqueezeValidationParams { squeezeSeed = seedVector, squeezeOutput = outputVector, squeezeState = stateVector }
  where
    seedVector                   = BS.pack $ toIntegralList $ section Map.! "seed"
    Text.Trifecta.Success output = parseString parseListWordIntegral mempty $ section Map.! "output"
    outputVector                 = BS.pack output
    Text.Trifecta.Success state  = parseString parseListWordIntegral mempty $ section Map.! "state"
    stateVector                  = VU.fromList state

shake128SqueezeBlocksCheck :: Shake128SqueezeValidationParams -> Int -> String -> TestTree
shake128SqueezeBlocksCheck params count variant = testCase ("shake128SqueezeBlocks (" ++ variant ++ ")")
    $ assertEqual "it is" (validatedOutput, validatedOutputState) (output, outputState)
  where
        validatedOutput       = squeezeOutput params
        validatedOutputState  = squeezeState params
        startingState         = shake128Absorb $ squeezeSeed params
        (output, outputState) = shake128SqueezeBlocks startingState count


data Shake256ValidationParams = Shake256ValidationParams { shake256Input    :: BS.ByteString
                                                           , shake256Output :: BS.ByteString
                                                           } deriving Show

shake256FromConfig :: Assignments -> Shake256ValidationParams
shake256FromConfig section = Shake256ValidationParams { shake256Input = inputVector, shake256Output = outputVector }
  where
    inputVector = BS.pack $ toIntegralList $ section Map.! "seed"
    Text.Trifecta.Success output = parseString parseListWordIntegral mempty $ section Map.! "output"
    outputVector = BS.pack output

shake256Check :: Shake256ValidationParams -> String -> TestTree
shake256Check params variant = testCase ("shake256 (" ++ variant ++ ")")
    $ assertEqual "it is" validatedResult calculatedResult
  where
        validatedResult = shake256Output params
        inputVector = shake256Input params
        calculatedResult = shake256 inputVector $ BS.length validatedResult


data KeccakF1600VectorsValidationParams = KeccakF1600VectorsValidationParams { keccakVectorsInput           :: BS.ByteString
                                                                               , keccakVectorsRate          :: Int
                                                                               , keccakVectorsOutput        :: Map.Map Int (VU.Vector Word64)
                                                                               , keccakVectorsUnifiedOutput :: VU.Vector Word64
                                                                               } deriving Show

keccakVectorsFromConfig :: Assignments -> KeccakF1600VectorsValidationParams
keccakVectorsFromConfig section = KeccakF1600VectorsValidationParams { keccakVectorsInput = inputBS
                                                                     , keccakVectorsRate = rate
                                                                     , keccakVectorsOutput = outputMap
                                                                     , keccakVectorsUnifiedOutput = unifiedVector
                                                                     }
  where
    rate                          = read $ section Map.! "r"
    inputBS                       = hexStringToByteString $ section Map.! "m"
    Text.Trifecta.Success unified = parseString parseListWordIntegral mempty $ section Map.! "unified"
    unifiedVector                 = VU.fromList unified
    Text.Trifecta.Success output  = parseString parseListIntegralMap mempty $ section Map.! "vectors"
    outputMap                     = Map.fromList $ fmap go output
      where
        go (key, value) = (key, VU.fromList value)

keccakVectorsCheck :: KeccakF1600VectorsValidationParams -> TestTree
keccakVectorsCheck params = testCase "keccakf1600 vectors check"
    $ assertEqual "it is" validatedResult calculatedResult
  where
    validatedResult  = keccakVectorsOutput params
    rate             = keccakVectorsRate params
    input            = keccakVectorsInput params
    calculatedResult = inputLoadVectors rate input


tests :: IO TestTree
tests = do
  config <- configFile

  let
      statePermuteParams :: StatePermuteValidationParams
      statePermuteParams = keccakFromConfig $ sectionNamed config "keccakf1600_statepermute"

      absorbParams :: Shake128AbsorbValidationParams
      absorbParams = absorbFromConfig $ sectionNamed config "shake128_absorb"

      absorbParams2 :: Shake128AbsorbValidationParams
      absorbParams2 = absorbFromConfig $ sectionNamed config "shake128_absorb_2"

      squeezeParams :: Shake128SqueezeValidationParams
      squeezeParams = squeezeFromConfig $ sectionNamed config "shake128_squeezeblocks"

      squeezeParams2 :: Shake128SqueezeValidationParams
      squeezeParams2 = squeezeFromConfig $ sectionNamed config "shake128_squeezeblocks_2"

      shake256Params :: Shake256ValidationParams
      shake256Params = shake256FromConfig $ sectionNamed config "shake256"

      shake256Params2 :: Shake256ValidationParams
      shake256Params2 = shake256FromConfig $ sectionNamed config "shake256_2"

      keccakVectorsParams :: KeccakF1600VectorsValidationParams
      keccakVectorsParams = keccakVectorsFromConfig $ sectionNamed config "keccak_absorb.loop"


  return $ testGroup "FIPS202 Tests" [ keccakPermuteCheck statePermuteParams
                                     , keccakVectorsCheck keccakVectorsParams
                                     , shake128AbsorbCheck absorbParams "#1"
                                     , shake128AbsorbCheck absorbParams2 "#2"
                                     , shake128SqueezeBlocksCheck squeezeParams 1 "#1"
                                     , shake128SqueezeBlocksCheck squeezeParams2 2 "#2"
                                     , shake256Check shake256Params "#1"
                                     , shake256Check shake256Params2 "#2"
                                     ]
