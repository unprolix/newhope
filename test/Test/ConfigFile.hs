{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes       #-}
{-# LANGUAGE Trustworthy       #-}
{-|
  Module        : Test.ConfigFile
  Description   : Tests our ability to parse our testing configuration files
  Copyright     : © Jeremy Bornstein 2019
  License       : Apache 2.0
  Maintainer    : jeremy@bornstein.org
  Stability     : experimental
  Portability   : portable

-}

module Test.ConfigFile where


import qualified Data.ByteString   as BS (ByteString)
import qualified Data.Map          as M
import           Prelude
import           Test.Tasty
import           Test.Tasty.HUnit
import           Text.RawString.QQ
import           Text.Trifecta     hiding (expected)

import qualified ConfigFile


maybeSuccess :: Result a -> Maybe a
maybeSuccess (Success a) = Just a
maybeSuccess _           = Nothing


assignmentCheck :: TestTree
assignmentCheck = testCase "Assignment Parsing" $ do
    let m = parseByteString ConfigFile.parseAssignment mempty input
        parsed = maybeSuccess m
        input = "simply=listen"
    assertEqual "simple assignment" parsed $ Just ("simply", "listen")


headerCheck :: TestTree
headerCheck = testCase "Header Parsing" $ do
    let m = parseByteString ConfigFile.parseHeader mempty input
        parsed = maybeSuccess m
        input = "[important]"
    assertEqual "header" parsed $ Just (ConfigFile.Header "important")


commentCheck :: TestTree
commentCheck = testCase "Comment Parsing" $ do
    let p = ConfigFile.skipComments >> ConfigFile.parseHeader
        m = parseByteString p mempty input
        parsed =  maybeSuccess m
        input = "; this is imporant\n[not_important]"
    assertEqual "skip comment before header" parsed $ Just (ConfigFile.Header "not_important")


sectionCheck :: TestTree
sectionCheck = testCase "Section Parsing" $ do
    let m = parseByteString ConfigFile.parseSection mempty input
        parsed = maybeSuccess m
        input  = "; super important\n[cheese_opinions]\ncheddar=fine"
        expected = Just (ConfigFile.Section
                            (ConfigFile.Header "cheese_opinions")
                            (M.fromList [("cheddar", "fine")]))
    assertEqual "skip comment before header" parsed expected


fullFile :: BS.ByteString
fullFile = [r|
; do not read this information
; you may find it artless
[animal_info]
crawler=wombat
bird=colibri

[charming]
quokka=super
|]


fileCheck :: TestTree
fileCheck = testCase "File Parsing" $ do
    let m = parseByteString ConfigFile.parseIni mempty fullFile
        parsed = maybeSuccess m
        sectionValues = M.fromList [ ("bird", "colibri")
                                   , ("crawler", "wombat")]
        charming = M.fromList [("quokka", "super")]
        expected = Just (ConfigFile.Config (M.fromList [ (ConfigFile.Header "animal_info", sectionValues)
                                                       , (ConfigFile.Header "charming", charming)]))
    assertEqual "can parse multiple sections" parsed expected



tests :: TestTree
tests = testGroup "ConfigFile tests" [ assignmentCheck
                                     , headerCheck
                                     , commentCheck
                                     , sectionCheck
                                     , fileCheck
                                     ]
