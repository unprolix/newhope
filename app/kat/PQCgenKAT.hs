{-# LANGUAGE Safe #-}
{-|
  Module        : PQCgenKAT
  Description   : Generate files for Known Answer Tests
  Copyright     : © Jeremy Bornstein 2019
  License       : Apache 2.0
  Maintainer    : jeremy@bornstein.org
  Stability     : experimental
  Portability   : portable

  PQCgenKAT means:
     Post Quantum Cryptography generate Known Answer Tests

  This generates test vectors (according to the NIST PQC spec) which
  should be identical (in filenames and contents) to the ones generated
  by the NewHope project's reference code.

  Automated tests elsewhere in this codebase which take those
  reference implementation vectors as input to verify that we generate
  the same data with the present implementation.

-}

module Main where

import Control.Monad
import Data.ByteString.Lazy.Builder (hPutBuilder)
import Data.Text                    as Text (pack)
import Filesystem                   (IOMode (WriteMode), isFile, removeFile, withTextFile)
import Filesystem.Path.CurrentOS    (fromText)
import System.Environment           (getArgs)
import System.Exit                  (ExitCode (ExitFailure), exitWith)

import qualified Crypto.NewHope as NewHope (N (N1024, N512))
import qualified KAT


outputTestVectors :: NewHope.N -> Int -> KAT.VectorGenerator -> IO ()
outputTestVectors n count gen = do
    let (fileName, vectors) = gen n count
    let filePath = fromText . pack $ fileName -- here's where we put it in some specific directory if we like
    fileExists <- isFile filePath
    when fileExists $ removeFile filePath
    withTextFile filePath WriteMode $ \ handle -> hPutBuilder handle vectors


outputCcaVectors :: NewHope.N -> IO ()
outputCcaVectors n = outputTestVectors n KAT.recordsToGenerate KAT.ccaKemTestVectors

outputCpaVectors :: NewHope.N -> IO ()
outputCpaVectors n = outputTestVectors n KAT.recordsToGenerate KAT.cpaKemTestVectors


main :: IO ()
main = do
    args <- getArgs
    runCommand args
  where
    runCommand ["all"]         = do outputCcaVectors NewHope.N512
                                    outputCcaVectors NewHope.N1024
                                    outputCpaVectors NewHope.N512
                                    outputCpaVectors NewHope.N1024

    runCommand ["cca", "512"]  =    outputCcaVectors NewHope.N512
    runCommand ["cca", "1024"] =    outputCcaVectors NewHope.N1024
    runCommand ["cpa", "512"]  =    outputCpaVectors NewHope.N512
    runCommand ["cpa", "1024"] =    outputCpaVectors NewHope.N1024

    runCommand _ = do
        putStrLn "Required arguments: ([ cca | cpa ] [ 512 | 1024 ]) | all"
        exitWith $ ExitFailure 1
