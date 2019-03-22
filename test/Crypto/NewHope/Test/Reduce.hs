{-# LANGUAGE Trustworthy #-}
{-|
  Module        : Crypto.NewHope.Test.Reduce
  Description   : Testing code for Reduce
  Copyright     : © Jeremy Bornstein 2019
  License       : Apache 2.0
  Maintainer    : jeremy@bornstein.org
  Stability     : experimental
  Portability   : portable

-}

module Crypto.NewHope.Test.Reduce where

import Data.Map
import Data.Word
import Test.Tasty
import Test.Tasty.HUnit
import Text.Trifecta

import ConfigFile
import Crypto.NewHope.Reduce (montgomeryReduce)


type Values = (Word32, Word16)

newtype MontgomeryReduceValidationParams = MontgomeryReduceValidationParams { values :: [Values]
                                                                            } deriving Show


mrFromConfig :: Config -> MontgomeryReduceValidationParams
mrFromConfig cfg = MontgomeryReduceValidationParams { values = vals }
  where
    section = cfg `sectionNamed` "montgomery_reduce"
    --Success vals = parseString parseValues mempty $ section ! "values"
    Success vals = parseString parseListIntegralPairs mempty $ section ! "values"


isMontgomeryReduceAccurate :: MontgomeryReduceValidationParams -> Bool
isMontgomeryReduceAccurate MontgomeryReduceValidationParams { values = v } = go v
  where
    go []                       = True
    go ((input, output) : rest) = montgomeryReduce input == output && go rest


configFile :: IO Config
configFile = fromFile "Reduce.cfg"

montgomeryReduceCheck :: MontgomeryReduceValidationParams -> TestTree
montgomeryReduceCheck params = testCase "montgomery reduce"
    (assertEqual "it is" True $ isMontgomeryReduceAccurate params)


tests :: IO TestTree
tests = do
    config <- configFile

    let mrParams :: MontgomeryReduceValidationParams
        mrParams = mrFromConfig config

    return $ testGroup "Reduce Tests" [montgomeryReduceCheck mrParams]
