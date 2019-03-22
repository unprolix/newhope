{-# LANGUAGE Safe #-}
{-|
  Module        : Crypto.NewHope.CPA_PKE
  Description   : IND-CPA-secure key encapsulation for the NewHope key exchange protocol
  Copyright     : © Jeremy Bornstein 2019
  License       : Apache 2.0
  Maintainer    : jeremy@bornstein.org
  Stability     : experimental
  Portability   : portable

  IND-CPA-secure key encapsulation for the NewHope key exchange protocol

-}

module Crypto.NewHope.CPA_PKE ( keypair
                              , encrypt
                              , decrypt

                              , publicKeyBytes
                              , secretKeyBytes
                              , cipherTextBytes

                              , PublicKey
                              , makePublicKey
                              , makePublicKeyFromBytes
                              , getPKData
                              , getPKPolyData
                              , getPKPoly
                              , getPKSeed

                              , SecretKey
                              , makeSecretKey
                              , makeSecretKeyFromBytes
                              , getSKPoly
                              , getSKPolyData

                              , CipherText
                              , makeCipherTextFromBytes  -- need to do this when decrypting
                              , getCTData
                              , getCTb
                              , getCTbData
                              , getCTv

                              , makePlainText   -- we use Plain instead of Clear so we have distinct abbreviations! i.e. pt != ct
                              , getPTData
                              ) where

import           Control.Applicative
import qualified Data.ByteString     as BS

import           Crypto.NewHope.FIPS202
import           Crypto.NewHope.Internals (N (N1024, N512), symBytes)
import qualified Crypto.NewHope.Internals as Internals
import           Crypto.NewHope.Poly      (Poly)
import qualified Crypto.NewHope.Poly      as Poly
import           Crypto.NewHope.RNG
import           StringUtils


-- * Counting bytes

-- | Size in bytes of a PublicKey
publicKeyBytes :: Internals.N -> Int
publicKeyBytes n = Poly.polyBytes n + symBytes

-- | Size in bytes of a SecretKey
secretKeyBytes :: Internals.N -> Int
secretKeyBytes = Poly.polyBytes

-- | Size in bytes of a CipherText
cipherTextBytes :: Internals.N -> Int
cipherTextBytes = liftA2 (+) Poly.polyBytes Poly.polyCompressedBytes


-- * PlainText

-- | This is a "msg" encoded from a Poly.  Since these are of constant
-- length even for different N, when restoring the Poly we need to
-- know N from elsewhere.
newtype PlainText = PlainText BS.ByteString deriving Eq

-- | Construct PlainText from ByteString
makePlainText :: BS.ByteString -> PlainText
makePlainText bs
    | not lengthOK = error "Invalid length for PlainText"
    | otherwise    = PlainText bs
  where
    len      = BS.length bs
    lengthOK = len == Poly.polyMsgBytes


-- | The raw data inside a PlainText
getPTData :: PlainText -> BS.ByteString
getPTData (PlainText ptData) = ptData


-- | The encoded Poly inside a PlainText
getPTv :: PlainText -> Internals.N -> Poly
getPTv (PlainText ptData) n = Poly.fromMsg n ptData



-- * PublicKey

newtype PublicKey = PublicKey BS.ByteString deriving Eq


-- | The N associated with this key
getPKn :: PublicKey -> Internals.N
getPKn (PublicKey pkData)
    | len == publicKeyBytes N512  = N512
    | len == publicKeyBytes N1024 = N1024
    | otherwise                   = error "Invalid N for PublicKey"
  where
    len = BS.length pkData


-- | In terms of the NewHope protocol, our PublicKey data is a
-- concatenation of the serialization of the Poly pk and the
-- public seed which generated the Poly a.
makePublicKey :: Poly -> Internals.Seed -> PublicKey
makePublicKey poly seed
    | not lengthOK = error "Invalid imputed length for PublicKey"
    | otherwise =    PublicKey bs
  where
    bs = BS.append poly' seed'
    poly' = Poly.toByteString poly
    seed' = Internals.getSeedData seed
    n = Poly.getN poly
    lengthOK = BS.length bs == publicKeyBytes n


-- | Construct PublicKey from ByteString
makePublicKeyFromBytes :: BS.ByteString -> PublicKey
makePublicKeyFromBytes pkData
    | not lengthOK = error "Invalid length for PublicKey"
    | otherwise    = PublicKey pkData
  where
    len      = BS.length pkData
    lengthOK = len == publicKeyBytes N512 || len == publicKeyBytes N1024


-- | The raw data inside a PublicKey
getPKData :: PublicKey -> BS.ByteString
getPKData (PublicKey pkData) = pkData


-- | The length of the encoded Poly pk in our encoded data.
getPKPolyBytes :: PublicKey -> Int
getPKPolyBytes pk = Poly.polyBytes $ getPKn pk


-- | The raw data encoding the Poly pk
getPKPolyData :: PublicKey -> BS.ByteString
getPKPolyData pk@(PublicKey pkData) = encoded
  where
    polyBytes = getPKPolyBytes pk
    encoded = BS.take polyBytes pkData


-- | The decoded Poly pk
getPKPoly :: PublicKey -> Poly
getPKPoly pk@(PublicKey pkData) = Poly.fromByteString encoded
  where
    polyBytes = getPKPolyBytes pk
    encoded = BS.take polyBytes pkData


-- | The Seed
getPKSeed :: PublicKey -> Internals.Seed
getPKSeed (PublicKey pkData) = Internals.makeSeed seedData
  where
    offset = BS.length pkData - symBytes
    seedData = BS.drop offset pkData



-- * SecretKey

newtype SecretKey = SecretKey BS.ByteString deriving Eq

-- | Construct from a Poly
makeSecretKey :: Poly -> SecretKey
makeSecretKey poly
    | not lengthOK = error "Invalid imputed N for SecretKey"
    | otherwise    = SecretKey bs
  where
    n        = Poly.getN poly
    bs       = Poly.toByteString poly
    lengthOK = BS.length bs == secretKeyBytes n


-- | Construct from a ByteString, which must contain a serialized Poly.
makeSecretKeyFromBytes :: BS.ByteString -> SecretKey
makeSecretKeyFromBytes bs
    | not lengthOK = error "Invalid length for SecretKey"
    | otherwise = SecretKey bs
  where
    len512   = secretKeyBytes N512
    len1024  = secretKeyBytes N1024
    len      = BS.length bs
    lengthOK = len == len512 || len == len1024


-- | The N associated with this key.  Prefixed with _ because nothing
-- uses this now, but it's good to have it here to document the
-- structure/contents and for possible future testing.
_getSKn :: SecretKey -> Internals.N
_getSKn (SecretKey skData)
    | len == len512  = N512
    | len == len1024 = N1024
    | otherwise      = error "Invalid N for SecretKey"
  where
    len     = BS.length skData
    len512  = secretKeyBytes N512
    len1024 = secretKeyBytes N1024


-- | The encoded Poly data, which also happens to be all of our data
getSKPolyData :: SecretKey -> BS.ByteString
getSKPolyData (SecretKey sk) = sk


-- | The encapsulated Poly
getSKPoly :: SecretKey -> Poly
getSKPoly (SecretKey sk) = Poly.fromByteString sk



-- * CipherText

newtype CipherText = CipherText BS.ByteString deriving Eq

-- TDOD: Useful for debugging. Should we retain it in the distribution?
instance Show CipherText where
   show (CipherText bs) = "CipherText: " ++ byteStringToHexString bs


-- | Construct a CipherText from two Polys.
makeCipherText :: Poly -> Poly -> CipherText
makeCipherText b v
    | not lengthOK = error "Invalid imputed length for CipherText"
    | otherwise    = CipherText bs
  where
    b' = Poly.toByteString b
    v' = Poly.compress v
    bs = BS.append b' v'

    lengthOK = let bn = Poly.getN b
                   vn = Poly.getN v
               in (bn == vn) && (BS.length bs == cipherTextBytes bn)


-- | Construct a CipherText from the data in a ByteString
makeCipherTextFromBytes :: BS.ByteString -> CipherText
makeCipherTextFromBytes bs
    | not lengthOK = error "Invalid length for CipherText"
    | otherwise    = CipherText bs
  where
    len      = BS.length bs
    len512   = cipherTextBytes N512
    len1024  = cipherTextBytes N1024
    lengthOK = len == len512 || len == len1024


-- | The N associated with this CipherText
getCTn :: CipherText -> Internals.N
getCTn (CipherText ctData)
    | len == len512  = N512
    | len == len1024 = N1024
    | otherwise      = error "Invalid N for CipherText"
  where
    len     = BS.length ctData
    len512  = cipherTextBytes N512
    len1024 = cipherTextBytes N1024


-- | The data encoding the encapsulated Poly b
getCTbData :: CipherText -> BS.ByteString
getCTbData ct@(CipherText ctData) = polyData
  where
    polyData  = BS.take polyBytes ctData
    n         = getCTn ct
    polyBytes = Poly.polyBytes n


-- | The encapsulated Poly b
getCTb :: CipherText -> Poly
getCTb = Poly.fromByteString . getCTbData


-- | The data encoding the encapsulated Poly v
getCTData :: CipherText -> BS.ByteString
getCTData (CipherText ctData) = ctData


-- | The encapsulated Poly v
getCTv :: CipherText -> Poly
getCTv ct@(CipherText ctData) = Poly.decompress polyData
  where
    polyData = BS.drop polyBytes ctData
    n = getCTn ct
    polyBytes = Poly.polyBytes n


-- | Deterministically generate public Poly a from Seed.  This is just
-- `Poly.uniform` but remains here for some degree of isomorphism with
-- the reference library.
genA :: Internals.N -> Internals.Seed -> Poly
genA = Poly.uniform



-- * Higher-level functions


-- | Generates a new keypair, along with the post-utilization Context.
keypair :: Context -> Internals.N -> (PublicKey, SecretKey, Context)
keypair ctx n = (pk, sk, ctx')
  where
    (z, ctx')               = randomBytes ctx symBytes
    (publicSeed, noiseSeed) = BS.splitAt symBytes $ shake256 z (2 * symBytes)

    shat = Poly.ntt $ Poly.sample n (Internals.makeSeed noiseSeed) 0
    ehat = Poly.ntt $ Poly.sample n (Internals.makeSeed noiseSeed) 1

    sk = makeSecretKey shat

    pk = let ahatShat = let ahat = genA n $ Internals.makeSeed publicSeed
                        in Poly.mulPointwise shat ahat
             bhat     = Poly.add ehat ahatShat
         in makePublicKey bhat $ Internals.makeSeed publicSeed


-- | Encrypt PlainText to CipherText
encrypt :: PlainText -> PublicKey -> Internals.Seed -> CipherText
encrypt pt pk coin = makeCipherText uhat vprime
  where
    n = getPKn pk
    v = getPTv pt n

    bhat = getPKPoly pk
    publicSeed = getPKSeed pk
    sprime = Poly.ntt $ Poly.sample n coin 0
    eprime = Poly.ntt $ Poly.sample n coin 1
    uhat = Poly.add eprime $ Poly.mulPointwise sprime (genA n publicSeed)

    vprime = Poly.add v $ Poly.add (Poly.sample n coin 2)
                         (Poly.invntt $ Poly.mulPointwise bhat sprime)


-- | Decrypt CipherText to PlainText.
decrypt :: CipherText -> SecretKey -> PlainText
decrypt c sk = PlainText msg
  where
    shat      = getSKPoly sk
    uhat      = getCTb c
    vprime    = getCTv c
    msg       = Poly.toMsg $ Poly.sub (Poly.invntt $ Poly.mulPointwise shat uhat) vprime

