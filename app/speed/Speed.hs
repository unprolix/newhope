{-# LANGUAGE Trustworthy #-}
{-|
  Module        : Speed
  Description   : Speed tests for NewHope.
  Copyright     : © Jeremy Bornstein 2019
  License       : Apache 2.0
  Maintainer    : jeremy@bornstein.org
  Stability     : experimental
  Portability   : portable

  Mirrors the functionality provided by the speed_* binaries in the
  reference C library. These are not part of our automated test suite
  per se because they don't result in pass/fail: just speed numbers.

  Because Haskell is non-strict, we have to be careful about how we do
  timing. I'm no expert, but evidence seems to indicate that the
  approach taken here is effective for the circumstances: we force
  evaluation of function arguments (with `deepseq` and associated
  NFData instances) before the function itself is called.  The
  function "timingAssumptionsValid" should evaluate to IO True only
  if we can trust our assumptions about how the system works, and it
  is called before the tests proper start.

-}

module Main where

import           Control.DeepSeq
import qualified Data.ByteString     as BS
import           Data.List           hiding (sum)
import qualified Data.Vector.Unboxed as VU
import           System.CPUTime

import           AuxUtil
import qualified Crypto.NewHope                  as NewHope
import qualified Crypto.NewHope.Internal.CCA_KEM as CCA_KEM
import qualified Crypto.NewHope.Internal.CPA_KEM as CPA_KEM
import qualified Crypto.NewHope.Internals        as Internals
import           Crypto.NewHope.Poly             (Poly (..))
import qualified Crypto.NewHope.Poly             as Poly hiding (Poly)
import qualified Crypto.NewHope.RNG              as RNG
import           Timing

-- | We use Null as the value of `deepseq` when we don't care about
-- the type of a prerequisite but still want to deepseq it.
data Null = Null deriving Show

-- | This instance lets us deepseq, which we need to control execution order during tests.
instance NFData Null
  where
    rnf _ = ()


testCount :: Int
testCount = 1000


median :: [Picoseconds] -> Picoseconds
median ns = ns' !! middle
  where
    ns'    = sort ns
    middle = Prelude.length ns `div` 2

mean :: [Picoseconds] -> Picoseconds
mean ns = total `div` items
  where
    total = sum ns
    items = fromIntegral $ length ns


summarize :: String -> NewHope.N -> [Picoseconds] -> IO ()
summarize name n values = putStrLn $ name ++ " (N=" ++ show (WrapN n) ++ "): " ++ timingStr
  where
    timingStr
      | meanMilliseconds > 1 = ": mean " ++ show meanMilliseconds ++ "ms; median: " ++ show medianMilliseconds ++ "ms"
      | meanMicroseconds > 1 = ": mean " ++ show meanMicroseconds ++ "μs; median: " ++ show medianMicroseconds ++ "μs"
      | meanFemtoseconds > 1 = ": mean " ++ show meanFemtoseconds ++ "fs; median: " ++ show medianFemtoseconds ++ "fs"
      | otherwise            = ": mean " ++ show meanPicoseconds  ++ "ps; median: " ++ show medianPicoseconds  ++ "ps"

    meanPicoseconds    = mean values
    medianPicoseconds  = median values

    meanMilliseconds   = milliseconds meanPicoseconds
    medianMilliseconds = milliseconds medianPicoseconds

    meanMicroseconds   = microseconds meanPicoseconds
    medianMicroseconds = microseconds medianPicoseconds

    meanFemtoseconds   = femtoseconds meanPicoseconds
    medianFemtoseconds = femtoseconds medianPicoseconds


-- | A TimingPair is a list of computations, the first of each which
-- is a prerequisite for the second. This is used to help isolate the
-- functions which we wish to time.
type TimingPair a b = (a, b)


-- | Given a list of TimingPair, return a list of times that each item
-- in the corresponding pair takes to compute. The only reason we care
-- about the timing of the first item is to ensure ourselves that our
-- assumptions about how evaluation works are warranted.  In most
-- cases we only want to use a wrapper around this function that
-- discards the first item of each pair.
timeEvaluationsAndPrereqs :: (NFData a, NFData b) => [TimingPair a b] -> IO [(Picoseconds, Picoseconds)]
timeEvaluationsAndPrereqs input = do
    output <- mapM go input
    -- we compute but ignore the first result for reasons detailed below
    return $ tail output
  where
    go :: (NFData c, NFData d) => (c, d) -> IO (Picoseconds, Picoseconds)
    go (c, d) = do
      start <- getCPUTime
      middle <- deepseq c getCPUTime
      end <- deepseq d getCPUTime
      return (middle - start, end - middle)


-- | Given a list of TimingPair, return a list of times that each
-- second item in the pair takes to evaluate, after evaluation of the
-- first. We require NFData so that we can call `deepseq` to force
-- evaluation to normal form (and thereby ensure that the value is
-- computed before we check the time).
--
-- In cases where the jig itself is not being tested, we don't care
-- about the timing of the prerequisite, so this function discards it.
timeEvaluationsWithPrereqs :: (NFData a, NFData b) => [TimingPair a b] -> IO [Picoseconds]
timeEvaluationsWithPrereqs input = fmap snd <$> timeEvaluationsAndPrereqs input


-- | Given a list of computations, return a list of times that each
-- takes to evaluate.  Can be used when the function to be tested
-- takes no arguments.  We require NFData so that we can call
-- `deepseq` to force evaluation to normal form (and thereby ensure
-- that the value is computed before we check the time).
timeEvaluations :: NFData a => [a] -> IO [Picoseconds]
timeEvaluations input = do
    output <- mapM go input
    -- we compute but ignore the first result for reasons detailed below
    return $ tail output
  where
    go :: NFData a => a -> IO Picoseconds
    go p = do
      start <- getCPUTime
      end <- deepseq p getCPUTime
      return $ end - start


-- | An automatic test to let us know (by evaluating to IO True) if we
-- can seemingly trust our assumptions about how values computed by
-- prerequisites are cached in practice.  If this returns IO False, we
-- probably can't trust our timing methodology: in that case,
-- something may have changed at the platform level.  Our test is that
-- on each of three iterations, the expensive-to-compute prerequisite
-- must take more than 20 times as long as the cheap-to-compute main
-- function.
timingAssumptionsValid :: IO Bool
timingAssumptionsValid = prerequisitesAreVastlyMoreExpensive $ compute 3
  where
    prerequisitesAreVastlyMoreExpensive :: (NFData a, NFData b) => [TimingPair a b] -> IO Bool
    prerequisitesAreVastlyMoreExpensive f = and <$> (fmap . fmap) check times
      where
        times = timeEvaluationsAndPrereqs f
        check (a, b) = (fromIntegral b * 100) / fromIntegral a < (0.05 :: Float)

    -- a list of pairs of computations, the first of each of which
    -- should be much slower than the second, which uses the results
    -- of the first.
    compute :: Int -> [TimingPair Int Int]
    compute count = foldr go [] [0 .. count]
      where
        go a results = new : results
          where
            expensive = fact $ 1000000 + a  -- takes time to compute. include 'a' so we avoid caching
            new = (expensive, testfn a)
            fact 0 = 1
            fact n = n * fact (n - 1)
            testfn b  = b + expensive       -- fast, apart from time spent computing expensive


-- | An infinite list of Seeds
seeds :: [Internals.Seed]
seeds = fst <$> next ctx
  where
    ctx = let randomSeed = RNG.makeRandomSeed $ BS.pack [0 .. 47]
          in RNG.randomBytesInit randomSeed Nothing 0
    next ctx_ = (seed, ctx_) : next ctx_'
      where
        (seedData, ctx_') = RNG.randomBytes ctx_ Internals.seedBytes
        seed = Internals.makeSeed seedData


-- * test computations


-- | Time computation of Poly.ntt
testPolyNTT :: Int -> NewHope.N -> [Poly]
testPolyNTT count n = foldr go [start] [0 .. count]
  where
    start :: Poly
    start = Poly $ VU.fromList [1 .. fromIntegral (Internals.value n)]
    go _a [] = []  -- non-occurring pattern included to shut up the compiler
    go _a results@(first : _rest) = nextResult : results
      where
        nextResult = Poly.ntt first


-- | Time computation of Poly.invntt
testPolyInvNTT :: Int -> NewHope.N -> [Poly]
testPolyInvNTT count n = foldr go [start] [0 .. count]
  where
    start :: Poly
    start = Poly $ VU.fromList [1 .. fromIntegral (Internals.value n)]
    go :: Int -> [Poly] -> [Poly]
    go _a [] = []  -- non-occurring pattern included to shut up the compiler
    go _a results@(first : _rest) = nextResult : results
      where
        nextResult = Poly.invntt first


-- | Time computation of Poly.uniform. Note that this differs from the
-- reference library's test of this function in that we use a
-- different seed for each call to uniform, in case the system
-- helpfully caches the result of that function call for us. The
-- reference library makes the exact same call n times, though there
-- is no likely risk of the result being cached in that case.
testPolyUniform :: Int -> NewHope.N -> [TimingPair Internals.Seed Poly]
testPolyUniform count n = foldr go [(head seeds, start)] $ take count $ drop 1 seeds
  where
    start :: Poly
    start = Poly $ VU.fromList [1 .. fromIntegral (Internals.value n)]
    go seed results = nextResult : results
      where
        nextResult = (seed, Poly.uniform n seed)


-- | Time computation of Poly.sample, using a unique Seed for each
-- invocation.
testPolySample :: Int -> NewHope.N -> [TimingPair Internals.Seed Poly]
testPolySample count n = foldr go [(head seeds, start)] $ take count $ drop 1 seeds
  where
    start :: Poly
    start = Poly $ VU.fromList [1 .. fromIntegral (Internals.value n)]
    go seed results = nextResult : results
      where
        nextResult = (seed, Poly.sample n seed 1)


-- | Time computation of CPA_KEM.keypair. Results are returned in two
-- TimingPair lists for use in subsequent tests.
testCPAKeypair :: Int -> NewHope.N -> ([TimingPair RNG.Context CPA_KEM.PublicKey], [TimingPair RNG.Context CPA_KEM.SecretKey])
testCPAKeypair count n = (pks, sks)
  where
    (_finalCTX, pks, sks) = foldr go (initialCTX, [], []) [0 .. count]
    seed = RNG.makeRandomSeed "Assise en tailleur face à l'écran, Nadine appuie"
    initialCTX = RNG.randomBytesInit seed Nothing 0
    go _a (ctx, pkResults, skResults) = (ctx', nextPK' : pkResults, nextSK' : skResults)
      where
        (nextPK, nextSK, ctx') = CPA_KEM.keypair ctx n
        nextPK' = (ctx, nextPK)
        nextSK' = (ctx, nextSK)


-- | Time computation of CCA_KEM.keypair. Results are returned in two
-- TimingPair lists for use in subsequent tests.
testCCAKeypair :: Int -> NewHope.N -> ([TimingPair RNG.Context CCA_KEM.PublicKey], [TimingPair RNG.Context CCA_KEM.SecretKey])
testCCAKeypair count n = (pks, sks)
  where
    (_finalCTX, pks, sks) = foldr go (initialCTX, [], []) [0 .. count]
    seed = RNG.makeRandomSeed "Assise en tailleur face à l'écran, Nadine appuie"
    initialCTX = RNG.randomBytesInit seed Nothing 0
    go _a (ctx, pkResults, skResults) = (ctx', nextPK' : pkResults, nextSK' : skResults)
      where
        (nextPK, nextSK, ctx') = CCA_KEM.keypair ctx n
        nextPK' = (ctx, nextPK)
        nextSK' = (ctx, nextSK)


-- | Time computation of CPA_KEM.encrypt.
testCPAEncrypt :: [CPA_KEM.PublicKey] -> [TimingPair Null CPA_KEM.CipherText]
testCPAEncrypt pks = snd $ foldr go (initialCTX, []) pks
  where
    seed = RNG.makeRandomSeed "Assise en tailleur face à l'écran, Nadine appuie"
    initialCTX = RNG.randomBytesInit seed Nothing 0
    go pk (ctx, results) = (ctx', nextResult : results)
      where
        (ct, _ss, ctx') = CPA_KEM.encrypt ctx pk
        prereq' = seq (ctx, pk) Null -- not worth the typing to expose this upwards; deepseq will take care of it
        nextResult = (prereq', ct)


-- | Time computation of CCA_KEM.encrypt.
testCCAEncrypt :: [CCA_KEM.PublicKey] -> [TimingPair Null CCA_KEM.CipherText]
testCCAEncrypt pks = snd $ foldr go (initialCTX, []) pks
  where
    seed = RNG.makeRandomSeed "Assise en tailleur face à l'écran, Nadine appuie"
    initialCTX = RNG.randomBytesInit seed Nothing 0
    go pk (ctx, results) = (ctx', nextResult : results)
      where
        (ct, _ss, ctx') = CCA_KEM.encrypt ctx pk
        prereq' = seq (ctx, pk) Null -- not worth the typing to expose this upwards; deepseq will take care of it
        nextResult = (prereq', ct)


-- | Time computation of CPA_KEM.decrypt.
testCPADecrypt :: [CPA_KEM.CipherText] -> [CPA_KEM.SecretKey] -> [TimingPair Null CPA_KEM.SharedSecret]
testCPADecrypt cts sks = foldr go [] $ zip cts sks
  where
    go (ct, sk) results = nextResult : results
      where
        prereq = seq (ct, sk) Null
        ss = CPA_KEM.decrypt ct sk
        nextResult = (prereq, ss)


-- | Time computation of CCA_KEM.decrypt.
testCCADecrypt :: [CCA_KEM.CipherText] -> [CCA_KEM.SecretKey] -> [TimingPair Null (Bool, CCA_KEM.SharedSecret)]
testCCADecrypt cts sks = foldr go [] $ zip cts sks
  where
    go :: (CCA_KEM.CipherText, CCA_KEM.SecretKey) -> [TimingPair Null (Bool, CCA_KEM.SharedSecret)] -> [TimingPair Null (Bool, CCA_KEM.SharedSecret)]
    go (ct, sk) results = nextResult : results
      where
        prereq = seq (ct, sk) Null -- not worth the typing to expose this upwards; deepseq will take care of it
        ss = CCA_KEM.decrypt ct sk
        nextResult = (prereq, ss)


-- | For tests that involve multiple stages of data, this version does
-- all of the non-timed work first. The chunks are organized so that a
-- garbage collector could save some space in-between unrelated
-- sections.
testN :: NewHope.N -> IO ()
testN n = do
  putStrLn ""
  putStrLn $ "*** Testing N = " ++ show (WrapN n)

  -- we add an extra test so that the first test will absorb any
  -- effects associated with dynamic loading of code or other
  -- subtleties that may apply. (In practice, the first test often
  -- takes significantly longer, so it seems reasonable not to count
  -- it.)
  let testCount' = testCount + 1

  polyNTTTimes <- timeEvaluations $ testPolyNTT testCount' n
  summarize "Poly NTT" n polyNTTTimes

  polyInvNTTTimes <- timeEvaluations $ testPolyInvNTT testCount' n
  summarize "Poly inverse NTT" n polyInvNTTTimes

  polyUniformTimes <- timeEvaluationsWithPrereqs $ testPolyUniform testCount' n
  summarize "Poly uniform" n polyUniformTimes

  polySampleTimes <- timeEvaluationsWithPrereqs $ testPolySample testCount' n
  summarize "Poly sample" n polySampleTimes


  putStr "Staging CPA computations for tests..."
  let (cpaPKs, cpaSKs)  = testCPAKeypair testCount' n
  let cpaCTs = testCPAEncrypt (snd <$> cpaPKs)
  let cpaSSs = testCPADecrypt (snd <$> cpaCTs) (snd <$> cpaSKs)
  putStrLn " Done."

  let cpaPKSKs = let go (pkPrereq, pk) (skPrereq, sk) = ((pkPrereq, skPrereq), (pk, sk))
                 in zipWith go cpaPKs cpaSKs

  cpaKeypairTimes <- timeEvaluationsWithPrereqs cpaPKSKs
  summarize "CPA_KEM.keypair" n cpaKeypairTimes

  cpaEncryptTimes <- timeEvaluationsWithPrereqs cpaCTs
  summarize "CPA_KEM.encrypt" n cpaEncryptTimes

  cpaDecryptTimes <- timeEvaluationsWithPrereqs cpaSSs
  summarize "CPA_KEM.decrypt" n cpaDecryptTimes

  ---

  putStr "Staging CCA computations for tests..."
  let (ccaPKs, ccaSKs) = testCCAKeypair testCount' n
  let ccaCTs = testCCAEncrypt (snd <$> ccaPKs)
  let ccaSSs = testCCADecrypt (snd <$> ccaCTs) (snd <$> ccaSKs)
  putStrLn " Done."

  let ccaPKSKs = let go (pkPrereq, pk) (skPrereq, sk) = ((pkPrereq, skPrereq), (pk, sk))
                 in zipWith go ccaPKs ccaSKs

  ccaKeypairTimes <- timeEvaluationsWithPrereqs ccaPKSKs
  summarize "CCA_KEM.keypair" n ccaKeypairTimes

  ccaEncryptTimes <- timeEvaluations ccaCTs
  summarize "CCA_KEM.encrypt" n ccaEncryptTimes

  ccaDecryptTimes <- timeEvaluations ccaSSs
  summarize "CCA_KEM.decrypt" n ccaDecryptTimes

  return ()


main :: IO ()
main = do
    putStr "*** Validating assumptions about timing.... "
    timingOK <- timingAssumptionsValid
    if timingOK
      then putStrLn "Validated."
      else error "Not validated. Timing results are questionable."

    putStrLn ""
    putStrLn $ "NOTE: Each named test in this run comprises " ++ show testCount ++ " individual test iterations."
    putStrLn ""

    testN NewHope.N512
    testN NewHope.N1024
