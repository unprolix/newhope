{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE Trustworthy #-}
{-# OPTIONS_HADDOCK prune #-}
{-|
  Module        : Crypto.NewHope.Internal.SeedExpander
  Description   : Seed expander for NewHope.
  Copyright     : © Jeremy Bornstein 2019
  License       : Apache 2.0
  Maintainer    : jeremy@bornstein.org
  Stability     : experimental
  Portability   : portable

  The "seed expander" is a facility specified by NIST for generating
  pseudorandom data given a seed. It is not used in the actual NewHope
  key exchange and is provided here for completeness/isomorphism with
  the NewHope C reference library.

  This module contains the actual implementation. Exposed definitions
  are in the 'Crypto.NewHope.SeedExpander' module.


  * Sample usage

  @
    let maxLen' = case maxLen 256 of Right value -> value
                                     Left x      -> error (show x)
    
    let diversifier = case createDiversifier (BSC.pack "12345678") of Right value -> value
                                                                      Left x      -> error (show x)
    
    let seed = (Internals.makeSeed "32 bytes of seed data go here...")
    
    let ctx = case seedexpanderInit seed diversifier maxLen' of Right value -> value
                                                                Left x      -> error (show x)
    
    let (ctx', buf) = case seedexpander ctx 16 of Right value -> value
                                                  Left x    r -> error (show x)
  @

-}

module Crypto.NewHope.Internal.SeedExpander where

import           Codec.Crypto.AES
import           Control.Monad.Except
import           Data.Bits
import           Data.Semigroup          ((<>))
import qualified Data.ByteString         as BS
import qualified Data.ByteString.Builder as Builder
import qualified Data.ByteString.Lazy    as BSL
import           Data.Word

import qualified Crypto.NewHope.Internals       as Internals
import qualified Crypto.NewHope.Internal.RNG    as RNG


-- | Error conditions detected in creation and use of 'Context' data
data RNGError = BadDiversifierLen | BadMaxLen | BadReqLen deriving (Show)


-- | Maintains state for a series of calls to generate pseudorandom data via 'seedexpander'.
data Context = Context { ctxBuffer          :: BS.ByteString
                       , ctxBufferPos       :: Word64
                       , ctxLengthRemaining :: Word64
                       , ctxKey             :: RNG.Key
                       , ctxCounter         :: RNG.V
                       } deriving (Eq)


-- | Contains extra seed material for initializing SeedExpander
newtype Diversifier = Diversifier BS.ByteString deriving Show

-- | Specifies eight bytes of data for use as part of the seed material to be expanded.
createDiversifier :: (MonadError RNGError m) => BS.ByteString -> m Diversifier
createDiversifier bs
    | BS.length bs /= 8 = throwError BadDiversifierLen
    | otherwise         = return $ Diversifier bs


-- | Contains the maximum number of bytes that a 'Context' will generate.
newtype MaxLen = MaxLen Word64

-- | Specifies the maximum number of bytes that a 'Context' will generate.
maxLen :: (MonadError RNGError m) => Word64 -> m MaxLen
maxLen n
    | n < 0 || n > 0x100000000 = throwError BadMaxLen
    | otherwise                = return $ MaxLen n
    

-- | Create a 'Context' for generation of data.
seedexpanderInit :: (MonadError RNGError m) => Internals.Seed -> Diversifier -> MaxLen -> m Context
seedexpanderInit (Internals.Seed seed) (Diversifier diversifier) (MaxLen maxLength) = return ctx
  where
    ctx = Context { ctxBuffer          = BS.pack $ replicate 16 0  -- irrelevant; will be discarded on first update
                  , ctxBufferPos       = 16                        -- at the end, so the first call will fill it
                  , ctxLengthRemaining = maxLength
                  , ctxKey             = RNG.createKey seed
                  , ctxCounter         = createCounter
                  }

    --    Structure of counter:
    --      00 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15
    --      DIVERSIFIER-----------| maxlen----| 00 00 00 00
    --                              MSB     LSB    

    createCounter :: RNG.V
    createCounter = RNG.createV value
      where
        maxlenFourBytes = fromIntegral $ maxLength .&. 0xFFffFFff
        zeroCounter = 0
        value = BS.pack (BS.unpack diversifier
                         ++ BSL.unpack (Builder.toLazyByteString (Builder.word32BE maxlenFourBytes))
                         ++ BSL.unpack (Builder.toLazyByteString (Builder.word32BE zeroCounter)))

  
-- | Generate pseudorandom data from the given 'Context'. The returned
-- pair contains the requested data and the next 'Context' to use.
seedexpander :: (MonadError RNGError m) => Context -> Word64 -> m (BS.ByteString, Context)
seedexpander ctx xlen
    | xlen >= ctxLengthRemaining ctx = throwError BadReqLen  -- i'd think it would be > and not >= but reference source' uses >=
    | xlen < 0                       = return (BS.pack [], ctx)
    | xlen <= (16 - bufferPos)       = return (existingBufferResult, ctx'0)
    | otherwise                      = do                      -- more than a single buffer's worth, or more than we have left in buffer
        (result', ctx') <- seedexpander ctx'1 xlen'
        return (restOfExistingBuffer <> result', ctx')
  where
    bufferPos = ctxBufferPos ctx
    bytesUsedOfBuffer = min (16 - bufferPos) (min xlen 16)                                -- how much from current buffer we'll use

    restOfExistingBuffer = BS.drop (fromIntegral bufferPos) (ctxBuffer ctx)               -- all of the unused bytes in the current buffer
    existingBufferResult = BS.take (fromIntegral bytesUsedOfBuffer) restOfExistingBuffer  -- the actual bytes we'll use from the buffer.
                                                                                          -- (only calculated if we don't need more bytes)

    -- For when we are returning bytes from our existing buffer.
    lengthRemaining = ctxLengthRemaining ctx - fromIntegral bytesUsedOfBuffer             -- how many bytes will be left in the Context?
    ctx'0           = ctx { ctxBufferPos = bufferPos + xlen,
                            ctxLengthRemaining = lengthRemaining
                          }

    -- When the existing buffer does not satisfy our appetite, prepare the next buffer and context.
    ctx'1 = ctx { ctxCounter         = RNG.incrementV $ ctxCounter ctx
                , ctxBufferPos       = 0
                , ctxBuffer          = nextBuffer
                , ctxLengthRemaining = lengthRemaining
                }
      where
        nextBuffer = crypt' ECB keyValue ecbModeDoesNotUseIV Encrypt payloadValue
          where
            RNG.Key keyValue    = ctxKey ctx
            RNG.V payloadValue  = ctxCounter ctx
            ecbModeDoesNotUseIV = BS.pack $ replicate 16 0  -- we'd use ⊥ but the AES library evaluates it, even for ECB

    xlen' = xlen - bytesUsedOfBuffer
