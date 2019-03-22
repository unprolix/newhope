{-# LANGUAGE Trustworthy #-}
{-|
  Module        : Crypto.NewHope.Test.RNG
  Description   : Testing code for RNG
  Copyright     : © Jeremy Bornstein 2019
  License       : Apache 2.0
  Maintainer    : jeremy@bornstein.org
  Stability     : experimental
  Portability   : portable

-}

module Crypto.NewHope.Test.RNG where

import           Codec.Crypto.AES
import qualified Data.ByteString       as BS
import qualified Data.ByteString.Char8 as BSC
import           Data.Map
import           Test.QuickCheck       (Arbitrary, arbitrary)
import           Test.Tasty
import           Test.Tasty.HUnit
import           Test.Tasty.QuickCheck as QC

import ConfigFile
import Crypto.NewHope.Internal.RNG
import StringUtils


configFile :: IO Config
configFile = fromFile "RNG.cfg"


newtype WrapKey = WrapKey Key

instance Show WrapKey
  where
    show (WrapKey (Key bs)) = "Key: " ++ byteStringToHexString bs


newtype WrapV = WrapV V deriving Eq

instance Show WrapV
  where
    show (WrapV (V bs)) = "V: " ++ byteStringToHexString bs


newtype WrapContext = WrapContext Context

instance Show WrapContext where
   show (WrapContext (Context key v reseedCounter)) = "Context {"
                                                      ++ "ctxKey = " ++ show (WrapKey key) ++ ", "
                                                      ++ "ctxV = " ++ show (WrapV v) ++ ", "
                                                      ++ "ctxReseedCounter = " ++ show reseedCounter ++ "}"



instance Arbitrary WrapKey where
  arbitrary = do
    key <- sequence [ arbitrary | _ <- [1 .. keyBytes]]
    return $ WrapKey $ createKey $ BSC.pack key

instance Arbitrary WrapV where
  arbitrary = do
    v <- sequence [ arbitrary | _ <- [1 .. vBytes]]
    return $ WrapV $ createV $ BSC.pack v

instance Arbitrary WrapContext
  where
    arbitrary = do
      wrappedKey <- arbitrary
      wrappedV <- arbitrary
      reseedCounter <- arbitrary

      let WrapKey key = wrappedKey
      let WrapV v = wrappedV

      return $ WrapContext Context { ctxKey = key
                                   , ctxV = v
                                   , ctxReseedCounter = abs reseedCounter
                                   }





data RNGValidationParams = RNGValidationParams { rngEntropy :: BS.ByteString
                                               , rngKey     :: BS.ByteString
                                               , rngV       :: BS.ByteString
                                               , rngBlock0  :: BS.ByteString
                                               , rngBlock1  :: BS.ByteString
                                               , rngBlock2  :: BS.ByteString
                                               } deriving Show

rngFromConfig :: Assignments -> RNGValidationParams
rngFromConfig section = RNGValidationParams { rngEntropy = hexStringToByteString $ section ! "entropy_input"
                                            , rngKey     = hexStringToByteString $ section ! "key"
                                            , rngV       = hexStringToByteString $ section ! "v"
                                            , rngBlock0  = hexStringToByteString $ section ! "block0"
                                            , rngBlock1  = hexStringToByteString $ section ! "block1"
                                            , rngBlock2  = hexStringToByteString $ section ! "block2"
                                            }


keyAndVCheck :: RNGValidationParams -> TestTree
keyAndVCheck params = testCase "rng key and v generation"
    $ assertBool "broken" allIsWell
  where
    entropy = makeRandomSeed $ rngEntropy params
    ctx = randomBytesInit entropy Nothing 256 -- note that the 256 is ignored!

    keyVerified = rngKey params
    Key keyActual = ctxKey ctx
    keyIsOK = keyVerified == keyActual

    vVerified = rngV params
    V vActual = ctxV ctx
    vIsOK = vVerified == vActual

    allIsWell = keyIsOK && vIsOK


blocksCheck :: RNGValidationParams -> TestTree
blocksCheck params = testCase "rng block generation"
    $ assertBool "broken" allIsWell
  where
    entropy = makeRandomSeed $ rngEntropy params
    ctx = randomBytesInit entropy Nothing 256 -- note that the 256 is ignored!

    block0Verified = rngBlock0 params
    (block0, ctx0) = randomBytes ctx $ BS.length block0Verified
    block0IsOK = block0Verified == block0

    block1Verified = rngBlock1 params
    (block1, ctx1) = randomBytes ctx0 $ BS.length block1Verified
    block1IsOK = block1Verified == block1

    block2Verified = rngBlock2 params
    (block2, _ctx2) = randomBytes ctx1 $ BS.length block2Verified
    block2IsOK = block2Verified == block2

    allIsWell = block0IsOK && block1IsOK && block2IsOK

blocksCheck' :: RNGValidationParams -> TestTree
blocksCheck' params = testCaseSteps "rng block generation" $ \ step -> do
    step "Making seed"
    let entropy = makeRandomSeed $ rngEntropy params
    let ctx = randomBytesInit entropy Nothing 256 -- note that the 256 is ignored!

    step "Generating block 0"
    let block0Verified = rngBlock0 params
    let (block0, ctx0) = randomBytes ctx $ BS.length block0Verified
    block0Verified == block0 @? "Block 0 not generated properly"

    step "Generating block 1"
    let block1Verified = rngBlock1 params
    let (block1, ctx1) = randomBytes ctx0 $ BS.length block1Verified
    block1Verified == block1 @? "Block 1 not generated properly"

    step "Generating block 2"
    let block2Verified = rngBlock2 params
    let (block2, _ctx2) = randomBytes ctx1 $ BS.length block2Verified
    block2Verified == block2 @? "Block 2 not generated properly"




testIncrementV :: TestTree
testIncrementV = testGroup "Incrementing a V" [ incrementCheckBasic
                                              , incrementCheckTwoWraps
                                              , incrementCheckFifteenWraps
                                              , incrementCheckWrapAround
                                              ]

incrementCheckBasic :: TestTree
incrementCheckBasic = testCase "Incrementing a v - final byte"
  (assertEqual "increment failed" (WrapV firstIncremented) (WrapV second)) where
     first = createV $ BS.pack [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]
     firstIncremented = incrementV first
     second = createV $ BS.pack [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,16]

incrementCheckTwoWraps :: TestTree
incrementCheckTwoWraps = testCase "Incrementing a v - two wraps"
  (assertEqual "increment failed" (WrapV firstIncremented) (WrapV second)) where
     first = createV $ BS.pack [0,1,2,3,4,5,6,7,8,9,10,11,12,13,255,255]
     firstIncremented = incrementV first
     second = createV $ BS.pack [0,1,2,3,4,5,6,7,8,9,10,11,12,14,0,0]

incrementCheckFifteenWraps :: TestTree
incrementCheckFifteenWraps = testCase "Incrementing a v - 15 wraps"
  (assertEqual "increment failed" (WrapV firstIncremented) (WrapV second)) where
     first = createV $ BS.pack [254,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255]
     firstIncremented = incrementV first
     second = createV $ BS.pack [255,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]

incrementCheckWrapAround :: TestTree
incrementCheckWrapAround = testCase "Incrementing a v - wraparound"
  (assertEqual "increment failed" (WrapV firstIncremented) (WrapV second)) where
     first = createV $ BS.pack [255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255]
     firstIncremented = incrementV first
     second = createV $ BS.pack [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]




-- AES tests are here because RNG is where we use AES.

newtype TestPlaintext = TestPlaintext { getText :: BS.ByteString } deriving (Eq, Show)

instance Arbitrary TestPlaintext where
  arbitrary = sized $ \ n -> do
    a <- sequence [ arbitrary | _ <- [1 .. n]]
    return $ TestPlaintext (BSC.pack a)


newtype AES256IV = AES256IV BS.ByteString deriving Show

aes256IVLength :: Int
aes256IVLength = 16

instance Arbitrary AES256IV
  where
    arbitrary = do
      a <- sequence [ arbitrary | _ <- [1 .. aes256IVLength]]
      return $ AES256IV $ BSC.pack a


-- using two different IVs to the crypt' function because ECB doesn't use the IV.
propCryptDecrypt :: WrapKey -> AES256IV -> AES256IV -> TestPlaintext -> Bool
propCryptDecrypt key iv iv2 plaintext = let
    WrapKey (Key key') = key
    AES256IV iv' = iv
    AES256IV iv2' = iv2
    TestPlaintext plaintext' = plaintext
    plaintext'' = pad ' ' 16 plaintext'
    encrypted = crypt' ECB key' iv' Encrypt plaintext''
    decrypted = crypt' ECB key' iv2' Decrypt encrypted
    decrypted' = BSC.take (BS.length plaintext') decrypted
  in plaintext' == decrypted'


-------------------

-- for manual investigation, not part of test suite
encryptionRoundtrip :: String -> IO BS.ByteString
encryptionRoundtrip plaintext = do
    WrapV (V iv') <- generate (arbitrary :: Gen WrapV)
    WrapKey (Key key') <- generate (arbitrary :: Gen WrapKey)
    let plaintext' = pad ' ' 16 (BSC.pack plaintext)
    let encrypted = crypt' ECB key' iv' Encrypt plaintext'
    let decrypted = crypt' ECB key' iv' Decrypt encrypted
    let decrypted' = BSC.take (Prelude.length plaintext) decrypted
    return decrypted'




tests :: IO TestTree
tests = do
  config <- configFile

  let rngParams :: RNGValidationParams
      rngParams = rngFromConfig $ config `sectionNamed` "rng"

  return $ testGroup "RNG Tests" [ QC.testProperty "round trip AES encryption" propCryptDecrypt
                                 , QC.testProperty "round trip AES encryption (plaintext size 100)" (mapSize (const 100) propCryptDecrypt)
                                 , QC.testProperty "round trip AES encryption (plaintext size 1025)" (mapSize (const 1025) propCryptDecrypt)
                                 , testIncrementV
                                 , blocksCheck' rngParams]
