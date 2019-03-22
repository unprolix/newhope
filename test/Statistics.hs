{-# LANGUAGE Trustworthy #-}
{-|
  Module        : Statistics
  Description   : Statistics helpers for testing.
  Copyright     : © Jeremy Bornstein 2019
  License       : Apache 2.0
  Maintainer    : jeremy@bornstein.org
  Stability     : experimental
  Portability   : portable

-}

module Statistics where

import Statistics.Distribution          hiding (mean)
import Statistics.Distribution.StudentT


-- | Confidence range using the Student T distribution
confidence :: Double -> [Integer] -> (Double, Double)
confidence factor as = (rangeLow, rangeHigh)
  where
    rangeLow = mean - base
    rangeHigh = mean + base
    n = length as
    df = fromIntegral $ n - 1
    mean = fromIntegral (sum as) / fromIntegral n
    σ = stddev as
    distribution = studentT df
    tQuantile = quantile distribution doubleTailProbability
    base = abs $ tQuantile * se
    se = σ / sqrt (fromIntegral n)
    doubleTailProbability = (1.0 - factor) / 2


-- | Standard deviation
stddev :: [Integer] -> Double
stddev as = sqrt $ realToFrac (sum squaredDiffFromMean / (len - 1))
  where
    as' = toRational <$> as
    len = fromIntegral $ length as
    mean = sum as' / len
    diffFromMean = (\a -> a - toRational mean) <$> as'
    squaredDiffFromMean = (^ (2::Int)) <$> diffFromMean
