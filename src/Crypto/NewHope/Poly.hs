{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric  #-}
{-# LANGUAGE Trustworthy    #-}
{-|
  Module        : Crypto.NewHope.Poly
  Description   : Polynomials and related operations.
  Copyright     : © Jeremy Bornstein 2019
  License       : Apache 2.0
  Maintainer    : jeremy@bornstein.org
  Stability     : experimental
  Portability   : portable

  Polynomials and related operations.

-}

module Crypto.NewHope.Poly where

import           Control.DeepSeq
import           Control.Monad.State         (join)
import           Data.Bits
import qualified Data.ByteString             as BS
import           Data.Int
import qualified Data.Vector.Unboxed         as VU
import qualified Data.Vector.Unboxed.Mutable as VUM
import           Data.Word
import           GHC.Generics                (Generic)
import           Prelude                     hiding (length)

import           Crypto.NewHope.FIPS202
import           Crypto.NewHope.Internals (N (N1024, N512))
import qualified Crypto.NewHope.Internals as Internals
import qualified Crypto.NewHope.NTT       as NTT
import           Crypto.NewHope.Precomp
import           Crypto.NewHope.Reduce    (montgomeryReduce)
import           MiscUtils


-- | Our Poly vectors are always of length N.
newtype Poly = Poly (VU.Vector Word16) deriving (Eq, Show, Generic, NFData)


-- | Bytes taken by regular encoded polynomials.
polyBytes :: N -> Int
polyBytes v = (14 * Internals.value v) `div` 8

-- | Bytes taken by a Poly-derived msg.
polyMsgBytes :: Int
polyMsgBytes = Internals.symBytes

-- | Bytes taken by a compressed Poly.
polyCompressedBytes :: N -> Int
polyCompressedBytes v = (3 * Internals.value v) `div` 8


-- | The length of this Poly
length :: Poly -> Int
length (Poly v) = VU.length v


-- | The parameter set to which this Poly belongs
getN :: Poly -> N
getN p = case length p of
           512  -> N512
           1024 -> N1024
           _    -> error "Unexpected Poly length"


-- | Fully reduces an integer modulo q in constant time.  Returns
-- integer in {0,...,q-1} congruent to x modulo q.
coeffFreeze :: Word16 -> Word16
coeffFreeze x = r'
  where
    q = fromIntegral Internals.q
    r = x `mod` q
    m = r - q
    c = fromIntegral (fromIntegral m :: Int16) :: Int16
    c' = shiftR c 15
    c'word = fromIntegral c' :: Word16
    r' = m `xor` ((r `xor` m) .&. c'word)


-- | computes |(x mod q) - Q/2|
flipabs :: Word16 -> Word16
flipabs x = fromIntegral $ xor m (r' + m)
  where
    q  :: Int
    q  = fromIntegral Internals.q
    r  = fromIntegral $ coeffFreeze x
    r' = r - (q `div` 2)
    m  = shiftR r' 15


-- | Deserialize
fromByteString :: BS.ByteString -> Poly
fromByteString a
    | not bytesOK = error $ "Invalid number (" ++ show bytes ++ ") of serialized bytes for Poly."
    | otherwise   = Poly result
  where
    bytes     = BS.length a
    bytes512  = polyBytes N512
    bytes1024 = polyBytes N1024
    bytesOK   = (bytes == bytes512) || (bytes == bytes1024)

    result   = VU.fromList $ fmap fromIntegral joined
    joined   = join folded
    folded   = Prelude.foldr go [] as
    as       = Prelude.take (bytes `div` 4) $ VU.fromList <$> chunk 7 (fromIntegral <$> BS.unpack a :: [Word16])

    go b c = [i0, i1, i2, i3] : c
      where
        b0 = b VU.! 0
        b1 = b VU.! 1
        b2 = b VU.! 2
        b3 = b VU.! 3
        b4 = b VU.! 4
        b5 = b VU.! 5
        b6 = b VU.! 6

        i0 =                        b0   .|. shiftL (b1 .&. 0x3f)  8
        i1 = shiftR b1 6 .|. shiftL b2 2 .|. shiftL (b3 .&. 0x0f) 10
        i2 = shiftR b3 4 .|. shiftL b4 4 .|. shiftL (b5 .&. 0x03) 12
        i3 = shiftR b5 2 .|. shiftL b6 6


-- | Serialize
toByteString :: Poly -> BS.ByteString
toByteString (Poly v) = results
  where
    results      = foldr go BS.empty inputVectors
    inputVectors = chunk 4 v

    go a = BS.append newItems
      where
        newItems = BS.pack $ fmap fromIntegral [i0, i1, i2, i3, i4, i5, i6]

        t0 = coeffFreeze $ a VU.! 0
        t1 = coeffFreeze $ a VU.! 1
        t2 = coeffFreeze $ a VU.! 2
        t3 = coeffFreeze $ a VU.! 3

        i0 =  t0 .&. 0xff
        i1 = shiftR t0  8 .|. shiftL t1 6
        i2 = shiftR t1  2
        i3 = shiftR t1 10 .|. shiftL t2 4
        i4 = shiftR t2  4
        i5 = shiftR t2 12 .|. shiftL t3 2
        i6 = shiftR t3  6


-- | Compression + serialization
compress :: Poly -> BS.ByteString
compress (Poly pData) = result
  where
    ts    = VU.map t pData
    input = chunk 8 ts

    t :: Word16 -> Word32
    t n = fromIntegral $ div (shiftL n' 3 + (q `div` 2)) q .&. 0x07
      where
        n' = fromIntegral $ coeffFreeze n
        q  = Internals.q

    result = BS.pack $ join $ fmap process input
      where
        process :: VU.Vector Word32 -> [Word8]
        process i = [ fromIntegral $       i0    .|. shiftL i1 3 .|. shiftL i2  6
                    , fromIntegral $ shiftR i2 2 .|. shiftL i3 1 .|. shiftL i4  4 .|. shiftL i5 7
                    , fromIntegral $ shiftR i5 1 .|. shiftL i6 2 .|. shiftL i7  5
                    ]
          where
            i0 = i VU.! 0
            i1 = i VU.! 1
            i2 = i VU.! 2
            i3 = i VU.! 3
            i4 = i VU.! 4
            i5 = i VU.! 5
            i6 = i VU.! 6
            i7 = i VU.! 7


-- | De-serialization and subsequent decompression of a polynomial;
-- approximate inverse of compress
decompress :: BS.ByteString -> Poly
decompress input = Poly $ VU.fromList result
  where
    inputChunks = chunk 3 $ VU.fromList (fromIntegral <$> BS.unpack input)
    process :: VU.Vector Word16 -> [Word16]
    process a = [        a0   .&. 7
                , shiftR a0 3 .&. 7
                , shiftR a0 6 .|. (shiftL a1 2 .&. 4)
                , shiftR a1 1 .&. 7
                , shiftR a1 4 .&. 7
                , shiftR a1 7 .|. (shiftL a2 1 .&. 6)
                , shiftR a2 2 .&. 7
                , shiftR a2 5
                ]
      where
        a0 = a VU.! 0
        a1 = a VU.! 1
        a2 = a VU.! 2

    finalize :: Word16 -> Word16
    finalize x = fromIntegral $ shiftR ((fromIntegral x :: Word32) * fromIntegral Internals.q + 4) 3
    result = fmap finalize $ join $ fmap process inputChunks


-- | Restore/convert from (32-byte) message
fromMsg :: N -> BS.ByteString -> Poly
fromMsg n msg = Poly vector'
  where
    msg' = VU.fromList $ BS.unpack msg
    empty = VU.replicate 256 0
    vector'
        | n == N512  = vector VU.++ vector
        | n == N1024 = vector VU.++ vector VU.++ vector VU.++ vector
        | otherwise  = error "Invalid N"
    vector = foldr go empty [0..31]
      where
        go i b = foldr go' b [0..7]
          where
            go' j = VU.modify (\v -> VUM.write v base value)
              where
                base = 8 * i + j
                mask = - ((fromIntegral (msg' VU.! i) `shiftR` j) .&. 1)
                value = mask .&. (fromIntegral Internals.q `div` 2)


-- | Convert polynomial to (32-byte) message
toMsg :: Poly -> BS.ByteString
toMsg p@(Poly x) = BS.pack result
  where
    result = foldr (.|.) 0 <$> chunked
    chunked = chunk 8 ts

    ts = t <$> [0..255]
      where
        n = getN p

        offsets
            | n == N512  = [0, 256]
            | n == N1024 = [0, 256, 512, 768]
            | otherwise  = error "Invalid vector size"

        tExtra :: Num a => a
        tExtra = fromIntegral $ if n == N1024
          then Internals.q
          else Internals.q `div` 2

        t :: Int -> Word8
        t i = fromIntegral shifted
          where
            offsets' = (+i) <$> offsets
            values   = (x VU.!) <$> offsets'
            values'  = flipabs <$> values
            summed   = sum values' - tExtra
            shifted  = shiftL (shiftR summed 15) (i .&. 7)


-- | Sample a polynomial deterministically from a seed, with output
-- polynomial looking uniformly random
uniform :: N -> Internals.Seed -> Poly
uniform n seed = Poly vector
  where
    Internals.Seed seed' = seed
    size = Internals.value n
    vector = let empty = VU.replicate size (0 :: Word16)
                 go :: Int -> VU.Vector Word16 -> VU.Vector Word16
                 go i victor = victor'
                   where
                     (_, victor') = let (buf, _) = let extseed = BS.snoc seed' (fromIntegral i)
                                                       staite  = shake128Absorb extseed
                                                   in shake128SqueezeBlocks staite 1
                                        bufBS    = VU.fromList $ BS.unpack buf
                                    in go' bufBS 0 0 victor

                     go' :: VU.Vector Word8 -> Int -> Int -> VU.Vector Word16 -> (Int, VU.Vector Word16)
                     go' buf ctr j vactor = if j' < shake128Rate && ctr' < 64
                                            then go' buf ctr' j' vactor'
                                            else (ctr', vactor')
                       where
                         val = let b0 = fromIntegral $ buf VU.! j
                                   b1 = fromIntegral $ buf VU.! (j + 1)
                               in b0 .|. shiftL b1 8 :: Word16
                         moveCounter = val < 5 * fromIntegral Internals.q
                         vactor' = if moveCounter
                                   then VU.modify (\v ->  VUM.write v (i * 64 + ctr) val) vactor
                                   else vactor
                         ctr' = if moveCounter
                                then ctr + 1
                                else ctr
                         j' = j + 2
               in foldr go empty [0..size `div` 64 - 1]


-- | The Hamming weight of a byte (the number of 1s)
hw :: Word8 -> Word8
hw a = sum [shiftR a i .&. 1  | i <- [0..7]]


-- | Sample a polynomial deterministically from a seed and a nonce,
-- with output polynomial close to centered binomial distribution with
-- parameter k=8
sample :: N -> Internals.Seed -> Word8 -> Poly
sample n seed nonce = Poly $ foldr go empty [0..size `div` 64 - 1]
  where
    size = Internals.value n
    empty = VU.replicate size 0
    seed' = let Internals.Seed seedData = seed
            in BS.snoc seedData nonce

    go i vector = foldr go' vector [0..63]
      where
        extseed = BS.snoc seed' $ fromIntegral i
        buf     = shake256 extseed 128

        go' j victor = victor'
          where
            a = fromIntegral.hw $ BS.index buf (2 * j)
            b = fromIntegral.hw $ BS.index buf (2 * j + 1)

            index   = 64 * i + j
            value   = a + fromIntegral Internals.q - b
            victor' = VU.modify (\v -> VUM.write v index value) victor


-- | Multiply two polynomials pointwise (i.e., coefficient-wise).
mulPointwise :: Poly -> Poly -> Poly
mulPointwise (Poly a) (Poly b) = Poly $ VU.zipWith go a b
-- NOTE: we don't check that these are the same length, which is fine given existing code.
-- NOTE: this is not commutative.
  where
    go c d = value
      where
        t     = montgomeryReduce (3186 * fromIntegral d) -- t is now in Montgomery domain
        value = montgomeryReduce (fromIntegral c * fromIntegral t) -- back in normal domain


-- | Add two polynomials
add :: Poly -> Poly -> Poly
add (Poly a) (Poly b) = Poly $ VU.zipWith go a b
-- NOTE: we don't check that these are the same length, which is fine given existing code.
-- NOTE: this is not commutative. should it be?
  where
    go c d = (c + d) `mod` fromIntegral Internals.q


-- | Subtract two polynomials
sub :: Poly -> Poly -> Poly
sub (Poly a) (Poly b) = Poly $ VU.zipWith go a b
  where
    q      = fromIntegral Internals.q
    go c d = (c + (3 * q) - d) `mod` q


-- | Forward NTT transform of a polynomial
-- input is assumed to have coefficients in bitreversed order output
-- has coefficients in normal order
ntt :: Poly  -- ^ input polynomial, in bitreversed order
    -> Poly  -- ^ transformed polynomial, in normal order
ntt p@(Poly r) = Poly result
  where
    n          = getN p
    multiplied = NTT.mulCoefficients r $ ψBitrevMontgomery n
    result     = NTT.ntt multiplied $ ωBitrevMontgomery n


-- | Inverse NTT transform of a polynomial
--
-- Output has coefficients in normal order
invntt :: Poly  -- ^ input, with coefficients in normal order
       -> Poly  -- ^ output, with coefficients in normal order
invntt p@(Poly r) = Poly result
  where
    n   = getN p
    r'     = NTT.bitrev r
    r''    = NTT.ntt r' $ ωInvBitrevMontgomery n
    result = NTT.mulCoefficients r'' $ ψInvMontgomery n
