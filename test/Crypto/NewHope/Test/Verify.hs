{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE Trustworthy       #-}
{-|
  Module        : Crypto.NewHope.Test.Verify
  Description   : Test Verify
  Copyright     : © Jeremy Bornstein 2019
  License       : Apache 2.0
  Maintainer    : jeremy@bornstein.org
  Stability     : experimental
  Portability   : portable

-}

module Crypto.NewHope.Test.Verify where


import           Control.Parallel
import qualified Data.ByteString         as BS
import qualified Data.ByteString.Char8   as BSC
import qualified Data.Vector             as V
import qualified Data.Vector.Unboxed     as VU
import           System.CPUTime
import           Test.QuickCheck.Monadic
import           Test.Tasty
import           Test.Tasty.QuickCheck   as QC


import Crypto.NewHope.Verify
import Statistics


sizeOfWrappedThings :: Int
sizeOfWrappedThings = 100

trialCount :: Int
trialCount = 100000  -- this is probably enough.


newtype WrappedVUUnbox a = WrappedVUUnbox (VU.Vector a) deriving Show

instance (Arbitrary a, VU.Unbox a) => Arbitrary (WrappedVUUnbox a) where
    arbitrary = fmap (WrappedVUUnbox . VU.fromList) arbitrary


newtype Wrapped a = Wrapped a deriving Show

instance {-# OVERLAPS #-} Show [Wrapped a]
  where
    show as = "[array of " ++ show (length as) ++ "]"

deWrapped :: Wrapped a -> a
deWrapped (Wrapped a) = a

instance (Semigroup a) => Semigroup (Wrapped a)
  where
    (Wrapped a) <> (Wrapped b) = Wrapped (a <> b)

instance (Semigroup a, Monoid a) => Monoid (Wrapped a)
  where
    mempty = Wrapped mempty
    mappend (Wrapped a) (Wrapped b) = Wrapped (mappend a b)

instance Functor Wrapped
  where
    fmap f (Wrapped a) = Wrapped (f a)

instance Arbitrary (Wrapped String)
  where
    arbitrary = Wrapped <$> vectorOf sizeOfWrappedThings genWrappedChar
      where
        genWrappedChar = elements $ ['a' .. 'z'] ++ ['A' .. 'Z'] ++ ['0' .. '9'] ++ " .,;:/|()[]{}!@#$%^&*<>"


instance Arbitrary (Wrapped BS.ByteString)
  where
    arbitrary = (fmap . fmap) BSC.pack arbitrary

instance (Arbitrary a, VU.Unbox a) => Arbitrary (Wrapped (V.Vector a))
  where
    arbitrary = (fmap . fmap) V.fromList v
      where
        v = Wrapped <$> vectorOf sizeOfWrappedThings arbitrary

instance Arbitrary (Wrapped (VU.Vector Char))
  where
    arbitrary = (fmap . fmap) VU.fromList arbitrary


genFixedLengthList :: (Arbitrary a) => Int -> Gen [a]
genFixedLengthList n = sequence [ arbitrary | _ <- [1 .. n]]


generateBigBytestringPair :: Gen ([Wrapped BS.ByteString], [Wrapped BS.ByteString])
generateBigBytestringPair = do
    a <- genFixedLengthList trialCount :: Gen [Wrapped BS.ByteString]
    b <- genFixedLengthList trialCount :: Gen [Wrapped BS.ByteString]
    return (a, b)

generateBigBytestringPairs :: Gen [(Wrapped BS.ByteString, Wrapped BS.ByteString)]
generateBigBytestringPairs = do
    a <- arbitrary :: Gen (Wrapped BS.ByteString)
    b <- arbitrary :: Gen (Wrapped BS.ByteString)
    rest <- generateBigBytestringPairs
    let firstItem = (a, b)
    return $ firstItem : rest


-----------------------

-- | Somewhat deep magic: Test a property in IO, which is required
-- here because we check the CPU time.  The basic idea is that f1 and
-- f2 (when called on the pairs of items from as and bs) should take
-- as close to the same amount of time as possible, and this test
-- should succeed iff we should be confident that this is true.
runTimingTests :: Monoid a => (a -> a -> b) -> (a -> a -> b) -> [Wrapped a] -> [Wrapped a] -> PropertyM IO ()
runTimingTests f1 f2 as bs = do allTimes <- run (traverse getTimeDifference $ zip as' bs')
                                let (low, high) = confidence 0.95 allTimes
                                -- TODO: just checking for 0 being included in the confidence interval is stupidly insufficient.
                                -- we should also check to see that the confidence interval is sufficiently narrow. but how narrow
                                -- is appropriate?
                                assert $ (low < 0) && (high > 0)
  where
    as' = deWrapped <$> as
    bs' = deWrapped <$> bs

    -- value returned represents the difference between measurement A and measurement B for a paired observation.
    getTimeDifference (a, b) = do
        start_1 <- getCPUTime
        time_1  <- pseq (f1 a b) getCPUTime
        start_2 <- getCPUTime
        time_2  <- pseq (f2 a b) getCPUTime
        let time_1' = time_1 - start_1
        let time_2' = time_2 - start_2
        return (time_1' - time_2')


-----------------------

propTimingPairBytestringCTC :: Property
propTimingPairBytestringCTC = forAll generateBigBytestringPair evaluator
  where
    evaluator :: ([Wrapped BS.ByteString], [Wrapped BS.ByteString]) -> Property
    evaluator (as, bs) = monadicIO $ runTimingTests chooseA chooseB as bs

    chooseA = constantTimeChoose True
    chooseB = constantTimeChoose False

-----------------------

propTimingPairBytestringCmov :: Property
propTimingPairBytestringCmov = forAll generateBigBytestringPair evaluator
  where
    evaluator :: ([Wrapped BS.ByteString], [Wrapped BS.ByteString]) -> Property
    evaluator (as, bs) = monadicIO $ runTimingTests chooseA chooseB as bs

    chooseA = cmov True
    chooseB = cmov False

-----------------------

propTimingPairBytestringVerify :: Property
propTimingPairBytestringVerify = forAll generateBigBytestringPair evaluator
  where
    evaluator :: ([Wrapped BS.ByteString], [Wrapped BS.ByteString]) -> Property
    evaluator (as, bs) = monadicIO $ runTimingTests chooseA chooseB as bs

    chooseA a b = verify a b -- will return False
    chooseB a _ = verify a a -- will return True (using the first argument)

propTimingPairBytestringVerify' :: Property
propTimingPairBytestringVerify' = forAll generateBigBytestringPair evaluator
  where
    evaluator :: ([Wrapped BS.ByteString], [Wrapped BS.ByteString]) -> Property
    evaluator (as, bs) = monadicIO $ runTimingTests chooseA chooseB as bs

    chooseA a b = verify a b -- Will return False
    chooseB _ b = verify b b -- Will return True (using the second argument)

-----------------------

tests :: TestTree
tests = testGroup "Verify Tests"
    [ adjustOptions $ QC.testProperty "verify ByteString comparison is constant time (#1)" propTimingPairBytestringVerify
    , adjustOptions $ QC.testProperty "verify ByteString comparison is constant time (#2)" propTimingPairBytestringVerify'
    , adjustOptions $ QC.testProperty "constantTimeChoose is constant time" propTimingPairBytestringCTC
    , adjustOptions $ QC.testProperty "cmov is constant time" propTimingPairBytestringCmov
    ]
  where
    adjustOptions :: TestTree -> TestTree
    adjustOptions = adjustOption setTests
                    . adjustOption setMaxSize
                    . adjustOption setVerbose
                    . adjustOption setShowReplay
      where
        setTests :: QuickCheckTests -> QuickCheckTests
        setTests _opt = QuickCheckTests 1

        setMaxSize :: QuickCheckMaxSize -> QuickCheckMaxSize
        setMaxSize _opt = QuickCheckMaxSize 1

        setVerbose :: QuickCheckVerbose -> QuickCheckVerbose
        setVerbose _opt = QuickCheckVerbose False

        setShowReplay :: QuickCheckShowReplay -> QuickCheckShowReplay
        setShowReplay _opt = QuickCheckShowReplay False
