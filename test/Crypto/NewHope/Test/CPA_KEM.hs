{-# LANGUAGE Trustworthy #-}
{-|
  Module        : Crypto.NewHope.Test.CPA_KEM
  Description   : Tests for IND-CPA-secure operations for NewHope.
  Copyright     : © Jeremy Bornstein 2019
  License       : Apache 2.0
  Maintainer    : jeremy@bornstein.org
  Stability     : experimental
  Portability   : portable

  These tests duplicate (and in some cases improve on) the CPA tests
  executed by the "test_*" binaries from the reference C code.

-}

module Crypto.NewHope.Test.CPA_KEM where


import           Data.Bits
import qualified Data.ByteString            as BS
import           Test.Tasty                 (TestTree, adjustOption, testGroup)
import           Test.Tasty.ExpectedFailure
import           Test.Tasty.QuickCheck      as QC hiding (output)


import           AuxUtil
import qualified Crypto.NewHope.Internal.CPA_KEM as CPA_KEM
import qualified Crypto.NewHope.Internal.RNG     as RNG
import qualified Crypto.NewHope.Internals        ()
import           Crypto.NewHope.Test.RNG
import           Util


-- Test the basic full key exchange.  Note that we use multiple ctx on
-- input, which is an improvement (and more realistic) as compared to
-- the reference code.
propKeyExchange :: WrapN -> WrapContext -> WrapContext -> Bool
propKeyExchange wrappedN wrappedCtx wrappedCtx2 = keyA == keyB
  where
    WrapN    n    = wrappedN
    WrapContext ctx  = wrappedCtx
    WrapContext ctx2 = wrappedCtx2

    (pk, skA, _ctx') = CPA_KEM.keypair ctx n         -- Alice generates a public key
    (sendb, keyB, _ctx'2) = CPA_KEM.encrypt ctx2 pk  -- Bob derives a secret key and creates a response
    keyA = CPA_KEM.decrypt sendb skA                 -- Alice uses Bob's response to get her secret key


-- Test that using random data as the secret key causes the key exchange to fail.
propInvalidSkA :: WrapN -> WrapContext -> WrapContext -> WrapContext -> Bool
propInvalidSkA wn wctx wctx2 wctx3 = keyA /= keyB
  where
    WrapN    n    = wn
    WrapContext ctx  = wctx
    WrapContext ctx2 = wctx2
    WrapContext ctx3 = wctx3

    (pk, _skA, _ctx') = CPA_KEM.keypair ctx n        -- Alice generates a public key
    (sendb, keyB, _ctx'2) = CPA_KEM.encrypt ctx2 pk  -- Bob derives the SharedSecret and creates a response
    keyA = CPA_KEM.decrypt sendb skA'               -- Alice tries to use Bob's response to get the SharedSecret
      where
        (randomData, _ctx'3) = RNG.randomBytes ctx3 $ CPA_KEM.secretKeyBytes n
        skA' = CPA_KEM.SecretKey randomData          -- Replace secret key with random values


-- | Test that the key exchange fails if three bits in the CipherText
-- are changed. This test (mirroring the reference C implementation)
-- changes the same three bits each time. An improved version of the
-- test would probably change three different bits.
propInvalidCiphertext :: WrapN -> WrapContext -> WrapContext -> Bool
propInvalidCiphertext wn wctx wctx2 = keyA /= keyB
  where
    WrapN n = wn
    WrapContext ctx = wctx
    WrapContext ctx2 = wctx2

    (pk, skA, _ctx') = CPA_KEM.keypair ctx n         -- Alice generates a public key
    (sendb, keyB, _ctx'2) = CPA_KEM.encrypt ctx2 pk  -- Bob derives a secret key and creates a response
    sendb' = mutateCipherText sendb                   -- alternate version of sendb to use for a bad decryption
    keyA = CPA_KEM.decrypt sendb' skA               -- Alice tries to use Bob's response to get her secret key


-- | Change three bits (always the same three) in the input
-- CipherText. This is the test from the reference library.
mutateCipherText :: CPA_KEM.CipherText -> CPA_KEM.CipherText
mutateCipherText (CPA_KEM.CipherText input) = CPA_KEM.CipherText output
  where
    (part1, part2) = BS.splitAt 42 input
    (part2a, part2b) = BS.splitAt 1 part2
    part2a' = BS.pack [xor (BS.index part2a 0) 0x23]
    output = BS.concat [part1, part2a', part2b]


-- | Each time, randomly mutate some number of bits in the ciphertext.
propInvalidCiphertextMutateNBits :: Int -> WrapN -> WrapContext -> WrapContext -> WrapContext -> Bool
propInvalidCiphertextMutateNBits bits wn wctx wctx2 wctx3 = keyA /= keyB
  where
    WrapN    n    = wn
    WrapContext ctx  = wctx
    WrapContext ctx2 = wctx2
    WrapContext ctx3 = wctx3

    (pk, skA, _ctx') = CPA_KEM.keypair ctx n                -- Alice generates a public key
    (sendb, keyB, _ctx'2) = CPA_KEM.encrypt ctx2 pk         -- Bob derives a secret key and creates a response
    (sendb', _ctx'3) = mutateCipherTextBits ctx3 bits sendb -- Change some byte in the ciphertext (i.e., encapsulated key)
    keyA = CPA_KEM.decrypt sendb' skA                       -- Alice uses the damaged version of Bob's response to get her secret key


mutateCipherTextBits :: RNG.Context -> Int -> CPA_KEM.CipherText -> (CPA_KEM.CipherText, RNG.Context)
mutateCipherTextBits ctx count (CPA_KEM.CipherText input) = (CPA_KEM.CipherText output, ctx')
  where
    (output, ctx') = mutateBits ctx count input


tests :: TestTree
tests = testGroup "CPA_KEM Tests" [ QC.testProperty "top level key exchange" propKeyExchange
                                  , QC.testProperty "invalid skA" propInvalidSkA
                                  , QC.testProperty "invalid ciphertext" propInvalidCiphertext
                                  , expectFail
                                    $ adjustOption (\ _ -> QuickCheckTests 256)
                                    $ QC.testProperty "invalid ciphertext (one random bit changed)"
                                    $ propInvalidCiphertextMutateNBits 1
                                  , expectFail
                                    $ adjustOption (\ _ -> QuickCheckTests 256)
                                    $ QC.testProperty "invalid ciphertext (two random bits changed)"
                                    $ propInvalidCiphertextMutateNBits 2
                                  , expectFail
                                    $ adjustOption (\ _ -> QuickCheckTests 512)
                                    $ QC.testProperty "invalid ciphertext (three random bits changed)"
                                    $ propInvalidCiphertextMutateNBits 3
                                  , expectFail
                                    $ adjustOption (\ _ -> QuickCheckTests 3200)
                                    $ QC.testProperty "invalid ciphertext (four random bits changed)"
                                    $ propInvalidCiphertextMutateNBits 4
                                  , QC.testProperty "invalid ciphertext (five random bits changed)" $ propInvalidCiphertextMutateNBits 5
                                  ]


