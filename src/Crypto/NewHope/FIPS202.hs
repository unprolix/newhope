{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE Trustworthy      #-}
{-|
  Module        : Crypto.NewHope.FIPS202
  Description   : Implements the FIPS202 (aka SHA-3) hashing algorithm.
  Copyright     : © Jeremy Bornstein 2019
  License       : Apache 2.0
  Maintainer    : jeremy@bornstein.org
  Stability     : experimental
  Portability   : portable

  Implements the FIPS202 (aka SHA-3) hashing algorithm.  This version
  is based on the version from the NewHope C reference implementation,
  which in turn was based on the public domain implementation in
  crypto_hash/keccakc512/simple/ from
  http://bench.cr.yp.to/supercop.html by Ronny Van Keer, and the
  public domain "TweetFips202" implementation from
  https://twitter.com/tweetfips202 by Gilles Van Assche, Daniel
  J. Bernstein, and Peter Schwabe.

  Note: When the author wrote this, he was unaware of the Keccak
  package that already existed in Hackage, which may have significantly
  differnent performance. It would not be a mistake to see if that
  implementation has more desirable characteristics than this one.

-}

module Crypto.NewHope.FIPS202 where

import           Data.Bits
import qualified Data.ByteString             as BS
import qualified Data.Map                    as Map
import qualified Data.Vector.Unboxed         as VU
import qualified Data.Vector.Unboxed.Mutable as VUM
import           Data.Word
import           Prelude                     hiding (round)

import StringUtils


-- | Our basic data: unboxed vector of 64-bit integers
type KeccakVector   = VU.Vector Word64

-- | Length of state vector
keccakStateLength :: Int
keccakStateLength = 25

-- | Size of blocks for SHAKE128
shake128Rate :: Int
shake128Rate = 168

-- | Size of blocks for SHAKE256
shake256Rate :: Int
shake256Rate = 136

-- | How many rounds of permutation should be performed
keccakF1600StatePermuteRoundsCount :: Int
keccakF1600StatePermuteRoundsCount = 24

-- | Starting point for computation
keccakEmpty :: KeccakVector
keccakEmpty = VU.replicate keccakStateLength 0




keccakFRoundConstants :: KeccakVector
keccakFRoundConstants = VU.fromList [ 0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
                                      0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
                                      0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
                                      0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
                                      0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
                                      0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]


rol :: Word64 -> Int -> Word64
rol a offset = shift a offset `xor` shift a (offset - 64)


-- | Given 8 bytes from a ByteString, compute a Word64 containing those bytes in little-endian order
load64 :: BS.ByteString  -- ^ Source data
       -> Int            -- ^ Offset within source from which to select data
       -> Word64
load64 input offset
    | BS.length trimmed < 8 = error ("TOO SHORT: \"" ++ (byteStringToHexString trimmed :: String) ++ "\"")
    | otherwise = foldl go a as
  where
    trimmed = BS.take 8 (BS.drop offset input)
    a : as  = reverse $ fromIntegral <$> BS.unpack trimmed
    go d c  = c .|. shift d 8


-- | Given 8 bytes from an unboxed Vector of bytes, compute a Word64 containing those bytes in little-endian order
load64' :: VU.Vector Word8 -- ^ Source data
        -> Int             -- ^ Offset within source from which to select data
        -> Word64
load64' input offset = foldl go a as
  where
    a : as = reverse $ fmap fromIntegral $ VU.toList $ VU.take 8 (VU.drop offset input)
    go d c = c .|. shift d 8


-- | Given a Word64, compute a ByteString containing the same value in little-endian order
store64 :: Word64 -> BS.ByteString
store64 value = BS.pack $ fmap fromIntegral [         value       .&. 0xFF,
                                                shift value $  -8 .&. 0xFF,
                                                shift value $ -16 .&. 0xFF,
                                                shift value $ -24 .&. 0xFF,
                                                shift value $ -32 .&. 0xFF,
                                                shift value $ -40 .&. 0xFF,
                                                shift value $ -48 .&. 0xFF,
                                                shift value $ -56 .&. 0xFF]

-- | Perform one round of permutation
keccakF1600StatePermute :: KeccakVector -> KeccakVector
keccakF1600StatePermute state' = runRounds state' 0
  where
    runRounds state round = if round >= keccakF1600StatePermuteRoundsCount - 2
                             then result
                             else runRounds result (round + 2)
      where
        aba = state VU.!  0
        abe = state VU.!  1
        abi = state VU.!  2
        abo = state VU.!  3
        abu = state VU.!  4
        aga = state VU.!  5
        age = state VU.!  6
        agi = state VU.!  7
        ago = state VU.!  8
        agu = state VU.!  9
        aka = state VU.! 10
        ake = state VU.! 11
        aki = state VU.! 12
        ako = state VU.! 13
        aku = state VU.! 14
        ama = state VU.! 15
        ame = state VU.! 16
        ami = state VU.! 17
        amo = state VU.! 18
        amu = state VU.! 19
        asa = state VU.! 20
        ase = state VU.! 21
        asi = state VU.! 22
        aso = state VU.! 23
        asu = state VU.! 24

        -- prepareTheta
        bca = aba `xor` aga `xor` aka `xor` ama `xor` asa
        bce = abe `xor` age `xor` ake `xor` ame `xor` ase
        bci = abi `xor` agi `xor` aki `xor` ami `xor` asi
        bco = abo `xor` ago `xor` ako `xor` amo `xor` aso
        bcu = abu `xor` agu `xor` aku `xor` amu `xor` asu

        -- thetaRhoPiChiIotaPrepareTheta(round  , A, E)
        da  = bcu `xor` rol bce 1
        de  = bca `xor` rol bci 1
        di  = bce `xor` rol bco 1
        do1 = bci `xor` rol bcu 1
        du  = bco `xor` rol bca 1

        aba2 = aba `xor` da

        bca2 = aba2
        age2 = age `xor` de
        bce2 = rol age2 44
        aki2 = aki `xor` di
        bci2 = rol aki2 43
        amo2 = amo `xor` do1
        bco2 = rol amo2 21
        asu2 = asu `xor` du
        bcu2 = rol asu2 14
        eba4 = bca2 `xor` complement bce2 .&. bci2
        eba5 = eba4 `xor` (keccakFRoundConstants VU.! round)
        ebe = bce2 `xor` complement bci2 .&. bco2
        ebi = bci2 `xor` complement bco2 .&. bcu2
        ebo = bco2 `xor` complement bcu2 .&. bca2
        ebu = bcu2 `xor` complement bca2 .&. bce2
        abo2 = abo `xor` do1
        bca3 = rol abo2 28
        agu2 = agu `xor` du
        bce3 = rol agu2 20
        aka2 = aka `xor` da
        bci3 = rol aka2 3
        ame2 = ame `xor` de
        bco3 = rol ame2 45
        asi2 = asi `xor` di
        bcu3 = rol asi2 61
        ega = bca3 `xor` complement bce3 .&. bci3
        ege = bce3 `xor` complement bci3 .&. bco3
        egi = bci3 `xor` complement bco3 .&. bcu3
        ego = bco3 `xor` complement bcu3 .&. bca3
        egu = bcu3 `xor` complement bca3 .&. bce3

        abe2 = abe `xor` de
        bca4 = rol abe2 1
        agi2 = agi `xor` di
        bce4 = rol agi2 6
        ako2 = ako `xor` do1
        bci4 = rol ako2 25
        amu2 = amu `xor` du
        bco4 = rol amu2  8
        asa2 = asa `xor` da
        bcu4 = rol asa2 18
        eka = bca4 `xor` complement bce4 .&. bci4
        eke = bce4 `xor` complement bci4 .&. bco4
        eki = bci4 `xor` complement bco4 .&. bcu4
        eko = bco4 `xor` complement bcu4 .&. bca4
        eku = bcu4 `xor` complement bca4 .&. bce4

        abu2 = abu `xor` du
        bca5 = rol abu2 27
        aga2 = aga `xor` da
        bce5 = rol aga2 36
        ake2 = ake `xor` de
        bci5 = rol ake2 10
        ami2 = ami `xor` di
        bco5 = rol ami2 15
        aso2 = aso `xor` do1
        bcu5 = rol aso2 56

        ema = bca5 `xor` complement bce5 .&. bci5
        eme = bce5 `xor` complement bci5 .&. bco5
        emi = bci5 `xor` complement bco5 .&. bcu5
        emo = bco5 `xor` complement bcu5 .&. bca5
        emu = bcu5 `xor` complement bca5 .&. bce5

        abi2 = abi `xor` di
        bca6 = rol abi2 62
        ago2 = ago `xor` do1
        bce6 = rol ago2 55
        aku2 = aku `xor` du
        bci6 = rol aku2 39
        ama2 = ama `xor` da
        bco6 = rol ama2 41
        ase2 = ase `xor` de
        bcu6 = rol ase2 2
        esa =   bca6 `xor` complement bce6 .&. bci6
        ese =   bce6 `xor` complement bci6 .&. bco6
        esi =   bci6 `xor` complement bco6 .&. bcu6
        eso =   bco6 `xor` complement bcu6 .&. bca6
        esu =   bcu6 `xor` complement bca6 .&. bce6

        -- prepareTheta
        bca7 = eba5 `xor` ega `xor` eka `xor` ema `xor` esa
        bce7 = ebe `xor` ege `xor` eke `xor` eme `xor` ese
        bci7 = ebi `xor` egi `xor` eki `xor` emi `xor` esi
        bco7 = ebo `xor` ego `xor` eko `xor` emo `xor` eso
        bcu7 = ebu `xor` egu `xor` eku `xor` emu `xor` esu

        -- thetaRhoPiChiIotaPrepareTheta(round+1, E, A)
        da2 = bcu7 `xor` rol bce7 1
        de2 = bca7 `xor` rol bci7 1
        di2 = bce7 `xor` rol bco7 1
        do2 = bci7 `xor` rol bcu7 1
        du2 = bco7 `xor` rol bca7 1

        eba6 = eba5 `xor` da2
        bca8 = eba6
        ege2 = ege `xor` de2
        bce8 = rol ege2 44
        eki2 = eki `xor` di2
        bci8 = rol eki2 43
        emo2 = emo `xor` do2
        bco8 = rol emo2 21
        esu2 = esu `xor` du2
        bcu8 = rol esu2 14
        aba3 = bca8 `xor` complement bce8 .&. bci8
        aba4 = aba3 `xor` (keccakFRoundConstants VU.! (round + 1))
        abe3 = bce8 `xor` complement bci8 .&. bco8
        abi3 = bci8 `xor` complement bco8 .&. bcu8
        abo3 = bco8 `xor` complement bcu8 .&. bca8
        abu3 = bcu8 `xor` complement bca8 .&. bce8

        ebo2 = ebo `xor` do2
        bca9 = rol ebo2 28
        egu2 = egu `xor` du2
        bce9 = rol egu2 20
        eka2 = eka `xor` da2
        bci9 = rol eka2 3
        eme2 = eme `xor` de2
        bco9 = rol eme2 45
        esi2 = esi `xor` di2
        bcu9 = rol esi2 61
        aga3 = bca9 `xor` complement bce9 .&. bci9
        age3 = bce9 `xor` complement bci9 .&. bco9
        agi3 = bci9 `xor` complement bco9 .&. bcu9
        ago3 = bco9 `xor` complement bcu9 .&. bca9
        agu3 = bcu9 `xor` complement bca9 .&. bce9

        ebe2 = ebe `xor` de2
        bcaA = rol ebe2 1
        egi2 = egi `xor` di2
        bceA = rol egi2 6
        eko2 = eko `xor` do2
        bciA = rol eko2 25
        emu2 = emu `xor` du2
        bcoA = rol emu2 8
        esa2 = esa `xor` da2
        bcuA = rol esa2 18
        aka3 = bcaA `xor` complement bceA .&. bciA
        ake3 = bceA `xor` complement bciA .&. bcoA
        aki3 = bciA `xor` complement bcoA .&. bcuA
        ako3 = bcoA `xor` complement bcuA .&. bcaA
        aku3 = bcuA `xor` complement bcaA .&. bceA

        ebu2 = ebu `xor` du2
        bcaB = rol ebu2 27
        ega2 = ega `xor` da2
        bceB = rol ega2 36
        eke2 = eke `xor` de2
        bciB = rol eke2 10
        emi2 = emi `xor` di2
        bcoB = rol emi2 15
        eso2 = eso `xor` do2
        bcuB = rol eso2 56
        ama3 = bcaB `xor` complement bceB .&. bciB
        ame3 = bceB `xor` complement bciB .&. bcoB
        ami3 = bciB `xor` complement bcoB .&. bcuB
        amo3 = bcoB `xor` complement bcuB .&. bcaB
        amu3 = bcuB `xor` complement bcaB .&. bceB

        ebi2 = ebi `xor` di2
        bcaC = rol ebi2 62
        ego2 = ego `xor` do2
        bceC = rol ego2 55
        eku2 = eku `xor` du2
        bciC = rol eku2 39
        ema2 = ema `xor` da2
        bcoC = rol ema2 41
        ese2 = ese `xor` de2
        bcuC = rol ese2 2
        asa3 = bcaC `xor` complement bceC .&. bciC
        ase3 = bceC `xor` complement bciC .&. bcoC
        asi3 = bciC `xor` complement bcoC .&. bcuC
        aso3 = bcoC `xor` complement bcuC .&. bcaC
        asu3 = bcuC `xor` complement bcaC .&. bceC

        result = VU.fromList [ aba4, abe3, abi3, abo3, abu3, aga3, age3, agi3,
                               ago3, agu3, aka3, ake3, aki3, ako3, aku3, ama3,
                               ame3, ami3, amo3, amu3, asa3, ase3, asi3, aso3, asu3]



inputLoadVectors :: Int -> BS.ByteString -> Map.Map Int KeccakVector
inputLoadVectors rate input = do
    let mlen = BS.length input
    let inputOffsets = [0, rate .. mlen - rate]
    Map.fromList $ fmap vectorAt inputOffsets
  where
    vectorAt offset = (offset, VU.fromList $ take keccakStateLength $ fmap valueAt [0 .. rate `div` 8 - 1] ++ repeat 0)
      where
        valueAt i = load64 input (offset + i * 8)



-- start with the starting vector, xor with the next vector in the list and then permute.
-- the operations need to take place from left to right.
unifiedInputLoadVectors :: KeccakVector -> Int -> BS.ByteString -> KeccakVector
unifiedInputLoadVectors start rate input = go start inputs
  where
    inputs = Map.elems $ inputLoadVectors rate input
    go start' [] = start'
    go start' (input' : inputs') = go nextStart inputs'
      where
        nextStart = keccakF1600StatePermute $ VU.zipWith xor start' input'


keccakAbsorb :: Int -> BS.ByteString -> Word8 -> KeccakVector
keccakAbsorb rate input domainSep = s'
  where
    s = unifiedInputLoadVectors keccakEmpty rate input
    s' = let loop ss i = ss VU.// [(i, (ss VU.! i) `xor` load64' t (8 * i))]
         in foldl loop s [0 .. rate `div` 8 - 1]

    -- given a rate, an input, and a domain byte, produce the "t"
    -- array used by the keccak absorb.
    -- NOTE: input length is smaller than rate. not sure where this comes from.
    t :: VU.Vector Word8
    t = VU.modify (\ v -> VUM.write v lastIndex (xor 128 (basic VU.! lastIndex))) basic
      where
        inputOffset = (inputLength `div` rate) * rate
        input' = BS.drop inputOffset input
        inputLength = BS.length input
        inputLength' = BS.length input'
        lastIndex = rate - 1
        basic = VU.concat [VU.fromList (BS.unpack input')
                         , VU.replicate 1 domainSep
                         , VU.replicate (rate - inputLength' - 1) 0
                         ]


-- | Absorb step of SHAKE128 XOF.
shake128Absorb :: BS.ByteString -> KeccakVector
shake128Absorb seed = keccakAbsorb shake128Rate seed 0x1f


-- | Squeeze step of SHAKE128 XOF. Squeezes full blocks of
-- shake128Rate each. May be used incrementally.
shake128SqueezeBlocks :: KeccakVector                  -- ^ Initial state
                      -> Int                           -- ^ Number of blocks to process
                      -> (BS.ByteString, KeccakVector) -- ^ Resulting output and state
shake128SqueezeBlocks = flip keccakSqueezeblocks shake128Rate


-- | Squeeze step of Keccak. Squeezes full blocks of 'rate' bytes
-- each. May be used incrementally.
keccakSqueezeblocks :: KeccakVector -> Int -> Int -> (BS.ByteString, KeccakVector)
keccakSqueezeblocks state rate blocks
    | blocks <= 0 = (BS.empty, state)
    |   otherwise = (BS.append output nextOutput, nextState)
  where
    state' = keccakF1600StatePermute state
    toEncode = VU.take (rate `div` 8) state'  -- just the first rate bytes (Word64 is eight of them!)
    output = VU.foldl toLSB BS.empty toEncode
    toLSB out inp = BS.append out (store64 inp)
    (nextOutput, nextState) = keccakSqueezeblocks state' rate (blocks - 1)


-- | Completely absorb input data with the SHAKE256 XOF.
shake256 :: BS.ByteString -- ^ Data to be absorbed
         -> Int           -- ^ Desired output length
         -> BS.ByteString
shake256 input outputLength = do
    let state = keccakAbsorb shake256Rate input 0x1F
    let nblocks = outputLength `div` shake256Rate
    let (output, state') = keccakSqueezeblocks state shake256Rate nblocks
    let extraBytes = outputLength `mod` shake256Rate
    let (extraOutput, _) = keccakSqueezeblocks state' shake256Rate 1
    if extraBytes == 0
      then output
      else BS.append output (BS.take extraBytes extraOutput)
