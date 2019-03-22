{-# LANGUAGE Trustworthy #-}
{-|
  Module        : LibTest
  Description   : Testing code for the Crypto.NewHope library
  Copyright     : © Jeremy Bornstein 2019
  License       : Apache 2.0
  Maintainer    : jeremy@bornstein.org
  Stability     : experimental
  Portability   : portable

-}

module Main where

import Test.Tasty

import qualified Crypto.NewHope.Test.CCA_KEM      as CCA_KEM
import qualified Crypto.NewHope.Test.CPA_KEM      as CPA_KEM
import qualified Crypto.NewHope.Test.FIPS202      as FIPS202
import qualified Crypto.NewHope.Test.NTT          as NTT
import qualified Crypto.NewHope.Test.Poly         as Poly
import qualified Crypto.NewHope.Test.Reduce       as Reduce
import qualified Crypto.NewHope.Test.RNG          as RNG
import qualified Crypto.NewHope.Test.SeedExpander as SeedExpander
import qualified Crypto.NewHope.Test.Verify       as Verify
import qualified Test.ConfigFile                  as ConfigFile
import qualified Test.KAT                         as KAT



main :: IO ()
main = do
  reduceTests       <- Reduce.tests
  rngTests          <- RNG.tests
  katTests          <- KAT.tests
  ccakemTests       <- CCA_KEM.tests
  nttTests          <- NTT.tests
  fips202Tests      <- FIPS202.tests
  polyTests         <- Poly.tests
  seedExpanderTests <- SeedExpander.tests

  defaultMain (testGroup "NewHope Library Tests" [ ConfigFile.tests
                                                 , Verify.tests
                                                 , reduceTests
                                                 , fips202Tests
                                                 , polyTests
                                                 , rngTests
                                                 , nttTests
                                                 , seedExpanderTests
                                                 , CPA_KEM.tests
                                                 , ccakemTests
                                                 , katTests
                                                 ])

  return ()
