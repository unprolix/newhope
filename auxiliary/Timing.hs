{-# LANGUAGE Safe #-}
{-|
  Module        : Timing
  Description   : Timing utilities
  Copyright     : © Jeremy Bornstein 2019
  License       : Apache 2.0
  Maintainer    : jeremy@bornstein.org
  Stability     : experimental
  Portability   : portable

-}

module Timing where


type Picoseconds  = Integer
type Milliseconds = Integer
type Microseconds = Integer
type Femtoseconds = Integer

milliseconds :: Picoseconds -> Milliseconds
milliseconds p = p `div` 1000000000

microseconds :: Picoseconds -> Microseconds
microseconds p = p `div` 1000000

femtoseconds :: Picoseconds -> Femtoseconds
femtoseconds p = p `div` 1000


showTime :: Picoseconds -> String
showTime picoseconds = result
  where
    result | asMilliseconds > 1 = show asMilliseconds ++ "ms"
           | asMicroseconds > 1 = show asMicroseconds ++ "µs"
           | asFemtoseconds > 1 = show asFemtoseconds ++ "fs"
           | otherwise          = show picoseconds    ++ "ps"

    asMilliseconds = milliseconds picoseconds
    asMicroseconds = microseconds picoseconds
    asFemtoseconds = femtoseconds picoseconds
