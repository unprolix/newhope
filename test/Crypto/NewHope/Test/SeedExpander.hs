{-# LANGUAGE Trustworthy #-}
{-|
  Module        : Crypto.NewHope.SeedExpander
  Description   : Testing code for SeedExpander
  Copyright     : © Jeremy Bornstein 2019
  License       : Apache 2.0
  Maintainer    : jeremy@bornstein.org
  Stability     : experimental
  Portability   : portable

-}

module Crypto.NewHope.Test.SeedExpander where


import qualified Data.ByteString  as BS
import           Data.Map
import           Data.Word
import           Test.Tasty
import           Test.Tasty.HUnit


import           ConfigFile
import qualified Crypto.NewHope.Internal.RNG          as RNG
import qualified Crypto.NewHope.Internal.SeedExpander as SE
import           Crypto.NewHope.Internals             (Seed, makeSeed)
import           Crypto.NewHope.Test.RNG              (WrapKey (..), WrapV (..))
import           StringUtils


configFile :: IO Config
configFile = fromFile "SeedExpander.cfg"

data SEContextParams = SEContextParams { ctxIndex           :: Int
                                       , ctxBuffer          :: BS.ByteString
                                       , ctxBufferPos       :: Word64
                                       , ctxLengthRemaining :: Word64
                                       , ctxKey             :: RNG.Key
                                       , ctxCounter         :: RNG.V
                                       }


makeBaseContext :: SEContextParams -> SE.Context
makeBaseContext seCtx = SE.Context { SE.ctxBuffer          = ctxBuffer seCtx
                                   , SE.ctxBufferPos       = ctxBufferPos seCtx
                                   , SE.ctxLengthRemaining = ctxLengthRemaining seCtx
                                   , SE.ctxKey             = ctxKey seCtx
                                   , SE.ctxCounter         = ctxCounter seCtx
                                   }

instance Show SEContextParams
  where
    show ctx = "SECP { n = " ++ show (ctxIndex ctx)
                         ++ ", buffer = " ++ byteStringToHexString (ctxBuffer ctx)
                         ++ ", bufferPos = " ++ show (ctxBufferPos ctx)
                         ++ ", lengthRemaining = " ++ show (ctxLengthRemaining ctx)
                         ++ ", key = " ++ show (WrapKey $ ctxKey ctx)
                         ++ ", payload = " ++ show (WrapV $ ctxCounter ctx)
                         ++ "}"


data SEValidationParams = SEValidationParams { seSeed        :: Seed
                                             , seDiversifier :: BS.ByteString
                                             , seCtxs        :: [SEContextParams]
                                             , seGenBufs     :: [BS.ByteString]
                                             }


seFromConfig :: Assignments -> SEValidationParams
seFromConfig section = SEValidationParams { seSeed        = seed
                                          , seDiversifier = diversifier
                                          , seCtxs        = ctxs
                                          , seGenBufs     = genBufs
                                          }

  where
    seed        = makeSeed $ hexStringToByteString $ section ! "seed"
    diversifier = hexStringToByteString $ section ! "diversifier"
    ctxs        = [getCtx 0, getCtx 1, getCtx 2, getCtx 3, getCtx 4]  -- order is important.
    genBufs     = [getGenBuf 1, getGenBuf 2, getGenBuf 3, getGenBuf 4]   -- order is important.

    -- ctx n results in genBuf n+1 and ctx n+1
    getGenBuf :: Int -> BS.ByteString
    getGenBuf n = result
      where
        Just result = hexStringToByteString <$> section !? ("genbuf" ++ show n)

    getCtx n = SEContextParams { ctxIndex           = n
                               , ctxBuffer          = buffer
                               , ctxBufferPos       = bufferPos
                               , ctxLengthRemaining = lengthRemaining
                               , ctxKey             = key
                               , ctxCounter         = counter
                               }
      where
        Just buffer          = hexStringToByteString <$> section !? ("buffer" ++ show n)
        Just bufferPos       = read <$> section !? ("buffer_pos" ++ show n)
        Just lengthRemaining = read <$> section !? ("length_remaining" ++ show n)
        Just key             = RNG.createKey . hexStringToByteString <$> section !? ("key" ++ show n)
        Just counter         = RNG.createV . hexStringToByteString <$> section !? ("ctr" ++ show n)


seCheck :: SEValidationParams -> TestTree
seCheck params = testCase "seedexpander"
    $ assertBool "broken" allIsWell
  where
    maxLengthBytes  = ctxLengthRemaining $ seCtxs params !! 0
    validGenBufs = seGenBufs params
    Right diversifier     = SE.createDiversifier (seDiversifier params) -- >>= return
    Right maxLen          = SE.maxLen maxLengthBytes
    Right  ctx0           = SE.seedexpanderInit (seSeed params) diversifier maxLen
    Right (genBuf1, ctx1) = SE.seedexpander ctx0 $ fromIntegral $ BS.length (validGenBufs !! 0)
    Right (genBuf2, ctx2) = SE.seedexpander ctx1 $ fromIntegral $ BS.length (validGenBufs !! 1)
    Right (genBuf3, ctx3) = SE.seedexpander ctx2 $ fromIntegral $ BS.length (validGenBufs !! 2)
    Right (genBuf4, ctx4) = SE.seedexpander ctx3 $ fromIntegral $ BS.length (validGenBufs !! 3)
    genBufs = [genBuf1, genBuf2, genBuf3, genBuf4]

    ctxs = [ctx0, ctx1, ctx2, ctx3, ctx4]
    ctxOK :: Int -> SE.Context -> Bool
    ctxOK n ctx = ctx == makeBaseContext (seCtxs params !! n)

    allIsWell = and (zipWith ctxOK [0, 1, 2, 3, 4] ctxs)
               && and (zipWith (==) genBufs validGenBufs)


-------------------

tests :: IO TestTree
tests = do
    config <- configFile

    let seParams :: SEValidationParams
        seParams = seFromConfig $ config `sectionNamed` "seedexpander"

    return $ testGroup "SeedExpander Test" [ seCheck seParams
                                           ]
