{-# LANGUAGE Trustworthy #-}
{-|
  Module        : Test.KAT
  Description   : Test validity of our KAT output
  Copyright     : © Jeremy Bornstein 2019
  License       : Apache 2.0
  Maintainer    : jeremy@bornstein.org
  Stability     : experimental
  Portability   : portable

  Tests to demonstrate that this implementation creates the same
  PQCkemKAT data as the reference C implementation.

-}

module Test.KAT where


import           Data.ByteString.Builder
import qualified Data.ByteString.Lazy      as BSL
import           Data.Text                 (Text)
import qualified Data.Text                 as Text
import           Data.Text.Encoding
import           Filesystem
import           Filesystem.Path.CurrentOS hiding (valid)
import           Test.Tasty
import           Test.Tasty.HUnit


import           AuxUtil
import qualified Crypto.NewHope.Internals as Internals
import           KAT


officialKATFilesPath :: String
officialKATFilesPath = "etc/official_kat/"


fileContents :: String -> IO Text
fileContents fn = readTextFile $ fromText . Text.pack $ fn


cpaKatCheck :: Internals.N -> String -> Text -> TestTree
cpaKatCheck n fileName valid =
    testCase ("CPA KAT validation, N=" ++ show (WrapN n)) $ do
        fileName @=? builtFileName
        validBSLazy @=? generated
  where
    (builtFileName, built) = KAT.cpaKemTestVectors n recordsToGenerate
    validBSLazy            = BSL.fromStrict validBS
    validBS                = encodeUtf8 valid
    generated              = toLazyByteString built


ccaKatCheck :: Internals.N -> String -> Text -> TestTree
ccaKatCheck n fileName valid =
    testCase ("CCA KAT validation, N=" ++ show (WrapN n)) $ do
        fileName @=? builtFileName
        validBSLazy @=? generated
  where
    (builtFileName, built) = KAT.ccaKemTestVectors n recordsToGenerate
    validBSLazy            = BSL.fromStrict validBS
    validBS                = encodeUtf8 valid
    generated              = toLazyByteString built



tests :: IO TestTree
tests = do
    validCpa512  <- fileContents $ officialKATFilesPath ++ "PQCkemKAT_896.rsp"
    validCpa1024 <- fileContents $ officialKATFilesPath ++ "PQCkemKAT_1792.rsp"
    validCca512  <- fileContents $ officialKATFilesPath ++ "PQCkemKAT_1888.rsp"
    validCca1024 <- fileContents $ officialKATFilesPath ++ "PQCkemKAT_3680.rsp"

    return $ testGroup "KAT tests"
      [ cpaKatCheck Internals.N512  "PQCkemKAT_896.rsp"  validCpa512
      , cpaKatCheck Internals.N1024 "PQCkemKAT_1792.rsp" validCpa1024
      , ccaKatCheck Internals.N512  "PQCkemKAT_1888.rsp" validCca512
      , ccaKatCheck Internals.N1024 "PQCkemKAT_3680.rsp" validCca1024
      ]
