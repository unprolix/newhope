{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE Trustworthy  #-}
{-|
  Module        : Crypto.NewHope.Test.CCA_KEM
  Description   : Tests for IND-CCA-secure operations for NewHope
  Copyright     : © Jeremy Bornstein 2019
  License       : Apache 2.0
  Maintainer:   : jeremy@bornstein.org
  Stability     : experimental
  Portability   : portable

  These tests duplicate (and in some cases improve on) the CCA tests
  executed by the "test_*" binaries from the reference C code.

-}

module Crypto.NewHope.Test.CCA_KEM where

import Control.Parallel
import System.CPUTime
import Test.Tasty                 (TestTree, adjustOption, testGroup)
import Test.Tasty.ExpectedFailure
import Test.Tasty.HUnit
import Test.Tasty.QuickCheck      as QC hiding (output)


import           AuxUtil
import qualified Crypto.NewHope.Internal.CCA_KEM as CCA_KEM
import qualified Crypto.NewHope.Internal.RNG     as RNG
import qualified Crypto.NewHope.Internals        as Internals
import           Crypto.NewHope.Test.RNG
import           Statistics
import           Util


-- | How many keypairs we use for timing analysis
keypairsToTestForTiming :: Int
keypairsToTestForTiming = 100


-- | Test the basic key exchange.  Note that we use multiple ctx on
-- input, which is an improvement (and more realistic test) as
-- compared to the reference code
propKeyExchange :: WrapN -> WrapContext -> WrapContext -> Bool
propKeyExchange wrappedN wrappedCtx wrappedCtx2 = success && keyA == keyB
  where
    WrapN       n    = wrappedN
    WrapContext ctx  = wrappedCtx
    WrapContext ctx2 = wrappedCtx2

    (pk, skA, _ctx') = CCA_KEM.keypair ctx n         -- Alice generates a public key
    (sendb, keyB, _ctx'2) = CCA_KEM.encrypt ctx2 pk  -- Bob derives a secret key and creates a response
    (success, keyA) = CCA_KEM.decrypt sendb skA      -- Alice uses Bob's response to get her secret key


-- | Test that using random data as the secret key causes the key
-- exchange to fail. This is the test from the reference code.
propInvalidSkA :: WrapN -> WrapContext -> WrapContext -> WrapContext -> Bool
propInvalidSkA wn wctx wctx2 wctx3 = not success && keyA /= keyB
  where
    WrapN    n    = wn
    WrapContext ctx  = wctx
    WrapContext ctx2 = wctx2
    WrapContext ctx3 = wctx3

    (pk, _skA, _ctx') = CCA_KEM.keypair ctx n        -- Alice generates a public key
    (sendb, keyB, _ctx'2) = CCA_KEM.encrypt ctx2 pk  -- Bob derives a secret key and creates a response
    (success, keyA) = CCA_KEM.decrypt sendb skA'     -- Alice uses Bob's response to get her secret key
      where
        skA' = CCA_KEM.SecretKey randomData          -- Replace secret key with random values
        (randomData, _ctx'3) = RNG.randomBytes ctx3 $ CCA_KEM.secretKeyBytes n


-- | Test to see if mutating a certain number of bits in the secret key causes the
-- key exchange to fail. (It only does sometimes until we get to 3 bits, when it does.)
propInvalidSkAMutateNBits :: Int -> WrapN -> WrapContext -> WrapContext -> Bool
propInvalidSkAMutateNBits bits wn wctx wctx2 = not success && keyA /= keyB
  where
    WrapN    n    = wn
    WrapContext ctx  = wctx
    WrapContext ctx2 = wctx2

    (pk, skA, ctx') = CCA_KEM.keypair ctx n             -- Alice generates a public key
    (skA', _ctx'2) = mutateSecretKeyBits ctx' bits skA  -- Change one or more bits in the secret key
    (sendb, keyB, _ctx2') = CCA_KEM.encrypt ctx2 pk     -- Bob derives a secret key and creates a response
    (success, keyA) = CCA_KEM.decrypt sendb skA'        -- Alice tries to use Bob's response to get her secret key


-- | Does randomly mutating one or more bits in the ciphertext cause
-- the decryption to fail? It does, even at one bit.
propInvalidCiphertextMutateNBits :: Int -> WrapN -> WrapContext -> WrapContext -> WrapContext -> Bool
propInvalidCiphertextMutateNBits bits wn wctx wctx2 wctx3 = not success && keyA /= keyB
  where
    WrapN    n    = wn
    WrapContext ctx  = wctx
    WrapContext ctx2 = wctx2
    WrapContext ctx3 = wctx3

    (pk, skA, _ctx') = CCA_KEM.keypair ctx n                 -- Alice generates a public key
    (sendb, keyB, _ctx'2) = CCA_KEM.encrypt ctx2 pk          -- Bob derives a secret key and creates a response
    (sendb', _ctx'3) = mutateCipherTextBits ctx3 bits sendb  -- Change some byte in the ciphertext (i.e., encapsulated key)
    (success, keyA) = CCA_KEM.decrypt sendb' skA             -- Alice uses the damaged version of Bob's response to get her secret key


-- | A TimingPair is a list of computations, the first of each which
-- is a prerequisite for the second. This is used to help isolate the
-- functions which we wish to time.
newtype TimingPair a b = TimingPair (a, b)


-- An infinite list of keypairs and accompanying ctx
keypairsWithCtx :: Internals.N -> [(CCA_KEM.PublicKey, CCA_KEM.SecretKey, RNG.Context)]
keypairsWithCtx n = go initialCtx
  where
    initialSeed = RNG.makeRandomSeed "Assise en tailleur face à l'écran, Nadine appuie"
    initialCtx = RNG.randomBytesInit initialSeed Nothing 0
    go ctx = (nextPk, nextSk, ctx') : go ctx'
      where
        (nextPk, nextSk, ctx') = CCA_KEM.keypair ctx n


mutateCipherTextBits :: RNG.Context -> Int -> CCA_KEM.CipherText -> (CCA_KEM.CipherText, RNG.Context)
mutateCipherTextBits ctx count (CCA_KEM.CipherText input) = (CCA_KEM.CipherText output, ctx')
  where
    (output, ctx') = mutateBits ctx count input

mutateSecretKeyBits :: RNG.Context -> Int -> CCA_KEM.SecretKey -> (CCA_KEM.SecretKey, RNG.Context)
mutateSecretKeyBits ctx count (CCA_KEM.SecretKey input) = (CCA_KEM.SecretKey output, ctx')
  where
    (output, ctx') = mutateBits ctx count input


assertKeyExchangeTiming :: IO Bool
assertKeyExchangeTiming = runTimingTests timingPairs
  where
    timingPairs = pairFor <$> take keypairsToTestForTiming (keypairsWithCtx Internals.N1024)
      where
        pairFor (pk, skA, ctx) = (TimingPair (prereqA, funcA), TimingPair (prereqB, funcB))
          where

            (!sendb, _keyB, ctx'2) = CCA_KEM.encrypt ctx pk         -- Bob derives a secret key and creates a response
            (!sendb', _ctx'3) = mutateCipherTextBits ctx'2 1 sendb  -- alternate version of sendb to use for a bad decryption

            prereqA = (sendb, skA)                                  -- Alice uses Bob's response to get her secret key
            funcA = CCA_KEM.decrypt sendb skA

            prereqB = (sendb', skA)                                 -- Alice tries, but Bob's response is bad.
            funcB = CCA_KEM.decrypt sendb' skA

    runTimingTests testPairs = do allTimes <- traverse getTimeDifference testPairs
                                  let (low, high) = confidence 0.95 allTimes
                                  -- TODO: just checking for 0 being included in the confidence interval is stupidly insufficient.
                                  -- we should also check to see that the confidence interval is sufficiently narrow. but how narrow
                                  -- is appropriate?
                                  return $ (low < 0) && (high > 0)
      where
        -- value returned represents the difference between measurement A and measurement B for a paired observation.
        getTimeDifference (TimingPair (prereqA, funcA), TimingPair (prereqB, funcB)) = do
          start1 <- pseq prereqA getCPUTime
          time1  <- pseq funcA getCPUTime
          start2 <- pseq prereqB getCPUTime
          time2  <- pseq funcB getCPUTime
          let time1' = time1 - start1
          let time2' = time2 - start2
          return (time1' - time2')


tests :: IO TestTree
tests = do
  assertKeyExchangeTiming' <- assertKeyExchangeTiming

  return $ testGroup "CCA_KEM Tests" [ QC.testProperty "top level key exchange" propKeyExchange
                                     , QC.testProperty "invalid skA" propInvalidSkA
                                     , expectFail $ adjustOption (\ _ -> QuickCheckTests 256) $ QC.testProperty "invalid skA (one random bit changed)" $ propInvalidSkAMutateNBits 1
                                     , QC.testProperty "invalid skA (two random bits changed)" $ propInvalidSkAMutateNBits 2
                                     , QC.testProperty "invalid skA (three random bits changed)" $ propInvalidSkAMutateNBits 3
                                     , adjustOption (\ _ -> QuickCheckTests 256) $ QC.testProperty "invalid ciphertext (one random bit changed)" $ propInvalidCiphertextMutateNBits 1
                                     , adjustOption (\ _ -> QuickCheckTests 4192) $ QC.testProperty "invalid ciphertext (two random bits changed)" $ propInvalidCiphertextMutateNBits 2
                                     , testCase "top level key exchange timing" (assertBool "relative timing not acceptable" assertKeyExchangeTiming')
                                     ]
