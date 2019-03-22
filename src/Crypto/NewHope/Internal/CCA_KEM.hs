{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE Safe         #-}
{-|
  Module        : Crypto.NewHope.CCA_KEM
  Description   : IND-CCA-secure operations for NewHope key exchange
  Copyright     : © Jeremy Bornstein 2019
  License       : Apache 2.0
  Maintainer    : jeremy@bornstein.org
  Stability     : experimental
  Portability   : portable

  IND-CPA-secure operations for the NewHope key exchange protocol. The
  algorithm name is either NewHope512-CPAKEM or NewHope1024-CPAKEM,
  depending on the value of N.

  This module contains the actual implementation. Exposed definitions
  are in the 'Crypto.NewHope.CPA_KEM' module.

-}

module Crypto.NewHope.Internal.CCA_KEM where


import           Control.DeepSeq
import qualified Data.ByteString as BS
import           StringUtils


import qualified Crypto.NewHope.CPA_PKE   as CPA_PKE
import           Crypto.NewHope.FIPS202
import           Crypto.NewHope.Internals (N (N1024, N512), symBytes)
import qualified Crypto.NewHope.Internals as Internals
import           Crypto.NewHope.Poly      (Poly)
import qualified Crypto.NewHope.Poly      as Poly
import           Crypto.NewHope.RNG
import           Crypto.NewHope.Verify


-- * Counting bytes of our components.  Note that all our sizes derive
-- at least in part from corresponding components in CPA_PKE.

-- | A public key is this many bytes long.
publicKeyBytes :: Internals.N -> Int
publicKeyBytes = CPA_PKE.publicKeyBytes

-- | A secret key is this many bytes long.
secretKeyBytes :: Internals.N -> Int
secretKeyBytes m = CPA_PKE.secretKeyBytes m + CPA_PKE.publicKeyBytes m + 2 * symBytes

-- | A ciphertext is this many bytes long.
cipherTextBytes :: Internals.N -> Int
cipherTextBytes m = CPA_PKE.cipherTextBytes m + symBytes -- Second part is for Targhi-Unruh


-- * SharedSecret

-- | The secret data posessed by both parties, resulting from the key
-- exchange protocol.
newtype SharedSecret = SharedSecret BS.ByteString deriving Eq


-- | We need this instance so that we can deepseq this data for performance tests.
instance NFData SharedSecret
  where
    rnf (SharedSecret skData) = deepseq skData ()


-- | Create a SharedSecret from a ByteString.
makeSharedSecret :: BS.ByteString -> SharedSecret
makeSharedSecret bs
    | not lengthOK = error "Invalid length for SharedSecret"
    | otherwise   = SharedSecret bs
  where
    lengthOK = BS.length bs == Internals.sharedSecretBytes


-- | Necessary for `KAT` only.
getSSData :: SharedSecret -> BS.ByteString
getSSData (SharedSecret ssData) = ssData


-- * PublicKey

-- | A public key; also the data sent from the first to the second party in the key exchange.
newtype PublicKey = PublicKey BS.ByteString deriving Eq

-- | We need this instance so that we can deepseq this data for performance tests.
instance NFData PublicKey
  where
    rnf _pk = ()

-- | Construct PublicKey from raw data
makePublicKey :: BS.ByteString -> PublicKey
makePublicKey bs
    | not lengthOK = error "Invalid length for PublicKey"
    | otherwise    = PublicKey bs
  where
    len = BS.length bs
    len512 = publicKeyBytes N512
    len1024 = publicKeyBytes N1024
    lengthOK = len == len512 || len == len1024


-- | The data inside the PublicKey
getPKData :: PublicKey -> BS.ByteString
getPKData (PublicKey pkData) = pkData


----------------------- Extracting items from within our data

-- | The N for this key
getPKn :: PublicKey -> Internals.N
getPKn (PublicKey pkData)
    | len == len512  = N512
    | len == len1024 = N1024
    | otherwise      = error "Invalid N for PublicKey"
  where
    len = BS.length pkData
    len512 = publicKeyBytes N512
    len1024 = publicKeyBytes N1024


-- | The encapsulated Poly
getPKPoly :: PublicKey -> Poly
getPKPoly pk@(PublicKey pkData) = Poly.fromByteString encoded
-- This is unused but important to retain as it is useful for documenting the structure of the data.
  where
    polyBytes = Poly.polyBytes $ getPKn pk
    encoded = BS.take polyBytes pkData


-- | The data for the encapsulated Poly
getPKPolyData :: PublicKey -> BS.ByteString
getPKPolyData pk@(PublicKey pkData) = encoded
-- This is unused but important to retain as it is useful for documenting the structure of the data.
  where
    polyBytes = Poly.polyBytes $ getPKn pk
    encoded = BS.take polyBytes pkData


-- | The data for the encapsulated Seed
getPKSeedData :: PublicKey -> BS.ByteString
getPKSeedData pk@(PublicKey pkData) = encoded
-- This is unused but important to retain as it is useful for documenting the structure of the data.
  where
    polyBytes = Poly.polyBytes $ getPKn pk
    encoded = BS.drop polyBytes pkData


-- * SecretKey

-- | A secret key; used to derive initiating party's copy of the
-- 'SharedSecret' in combination with a 'CipherText' from the
-- responding party.
newtype SecretKey = SecretKey BS.ByteString deriving Eq

-- | We need this instance so that we can deepseq this data during performance tests.
instance NFData SecretKey
  where
    rnf _sk = ()

-- | Construct from raw data
makeSecretKey :: BS.ByteString -> SecretKey
makeSecretKey bs
    | not lengthOK = error "Invalid length for SecretKey"
    | otherwise    = SecretKey bs
  where
    len = BS.length bs
    len512 = secretKeyBytes N512
    len1024 = secretKeyBytes N1024
    lengthOK = len == len512 || len == len1024


-- | The N for this key
getSKn :: SecretKey -> Internals.N
getSKn (SecretKey skData)
    | len == len512  = N512
    | len == len1024 = N1024
    | otherwise      = error "Invalid N for SecretKey"
  where
    len = BS.length skData
    len512 = secretKeyBytes N512
    len1024 = secretKeyBytes N1024


----------------------- Extracting items from within our data

-- | The raw data comprising the SecretKey
getSKData :: SecretKey -> BS.ByteString
getSKData (SecretKey skData) = skData


-- | Raw data for the encapsulated CPA_PKE.SecretKey, which itself is an encoded Poly.
getSkPkeSecretKeyData :: SecretKey -> BS.ByteString
getSkPkeSecretKeyData sk@(SecretKey skData) = encoded
  where
    secretKeyBytes' = CPA_PKE.secretKeyBytes $ getSKn sk
    encoded = BS.take secretKeyBytes' skData


-- | The encapsulated CPA_PKE.SecretKey
getSkSecretKey :: SecretKey -> CPA_PKE.SecretKey
getSkSecretKey sk = CPA_PKE.makeSecretKeyFromBytes $ getSkPkeSecretKeyData sk


-- | Raw data for the encapsulated CPA_PKE.PublicKey
getSkPkePublicKeyData :: SecretKey -> BS.ByteString
getSkPkePublicKeyData sk@(SecretKey skData) = encoded
  where
    n = getSKn sk
    secretKeySize = CPA_PKE.secretKeyBytes n
    publicKeySize = CPA_PKE.publicKeyBytes n
    encoded = bsRange skData secretKeySize publicKeySize


-- | The encapsulated CPA_PKE.PublicKey
getSkPkePublicKey :: SecretKey -> CPA_PKE.PublicKey
getSkPkePublicKey = CPA_PKE.makePublicKeyFromBytes . getSkPkePublicKeyData


-- | The encapsulated hash
getSkPkHash :: SecretKey -> BS.ByteString
getSkPkHash sk@(SecretKey skData) = encoded
  where
    n = getSKn sk
    secretKeySize = CPA_PKE.secretKeyBytes n
    publicKeySize = CPA_PKE.publicKeyBytes n
    offset = secretKeySize + publicKeySize
    encoded = bsRange skData offset symBytes

-- | I think this is called Z officially -- used as random data for failures. Does it have another use?
getSkZ :: SecretKey -> BS.ByteString
getSkZ sk@(SecretKey skData) = encoded
  where
    n = getSKn sk
    secretKeySize = CPA_PKE.secretKeyBytes n
    publicKeySize = CPA_PKE.publicKeyBytes n
    offset = secretKeySize + publicKeySize + symBytes
    encoded = bsRange skData offset symBytes

-- * CipherText

-- | Secret (encrypted) data sent from the responding party back to
-- the initiating party, used for initiating party to derive the
-- 'SharedSecret'.
newtype CipherText = CipherText BS.ByteString deriving Eq

-- | We need this instance so that we can deepseq this data for performance tests.
instance NFData CipherText
  where
    rnf _sk = ()


-- | Construct from raw data. composed of CPA_PKE.cipherTextBytes
-- (polyBytes + polyCompressedBytes) and then symBytes (Targhi-Unruh
-- hash)
makeCipherText :: BS.ByteString -> CipherText
makeCipherText bs
    | not lengthOK = error "Invalid length for CipherText"
    | otherwise    = CipherText bs
  where
    len = BS.length bs
    len512 = cipherTextBytes N512
    len1024 = cipherTextBytes N1024
    lengthOK = len == len512 || len == len1024

-- | The N for this CipherText
getCTn :: CipherText -> Internals.N
getCTn (CipherText ctData)
    | len == len512  = N512
    | len == len1024 = N1024
    | otherwise      = error "Invalid N for CipherText"
  where
    len = BS.length ctData
    len512 = cipherTextBytes N512
    len1024 = cipherTextBytes N1024


-- | The raw data for this CipherText
getCTData :: CipherText -> BS.ByteString
getCTData (CipherText ctData) = ctData


-- | The encapsulated CPA_PKE.CipherText data
getCtCTData :: CipherText -> BS.ByteString
getCtCTData ct@(CipherText ctData) = encoded
  where
    n = getCTn ct
    len = CPA_PKE.cipherTextBytes n
    encoded = BS.take len ctData


-- | The encapsulated CPA_PKE.CipherText
getCtCT :: CipherText -> CPA_PKE.CipherText
getCtCT ct = CPA_PKE.makeCipherTextFromBytes $ getCtCTData ct


-- * Top-level operations


-- | The first step of the NewHope key exchange protocol. Called by
-- the initiating party, generates 'PublicKey' and 'SecretKey'. The
-- 'PublicKey' is sent to the receiving party for the next step in the
-- protocol.
keypair :: Context -> Internals.N -> (PublicKey, SecretKey, Context)
keypair ctx n = (makePublicKey pkData, makeSecretKey skData, ctx1)
  where
    (cpaPkePk, cpaPkeSk, ctx0) = CPA_PKE.keypair ctx n

    (extra, ctx1) = randomBytes ctx0 symBytes

    pkData = CPA_PKE.getPKData cpaPkePk -- all the data -- which is an encoded poly and a seed
    skParts = [ CPA_PKE.getSKPolyData cpaPkeSk
              , pkData
              , shake256 pkData symBytes
              , extra
              ]
    skData = foldr BS.append BS.empty skParts  -- there must be a more idiomatic way to join a list of BSs


-- | For the provided 'PublicKey', generates a 'CipherText' and
-- 'SharedSecret'.  Called by the receiving party, this produces that
-- party's version of the 'SharedSecret' and also the message to
-- transmit to the initiating party ('CipherText').
encrypt :: Context -> PublicKey -> (CipherText, SharedSecret, Context)
encrypt ctx pk = (makeCipherText ctData, makeSharedSecret ss, ctx')
  where
    pkData = getPKData pk

    (buf, ctx') = randomBytes ctx symBytes
    bufP1Shaken = shake256 buf symBytes                              -- Don't release system RNG output

    (coin0, coin12) = let bufPart2 = shake256 pkData symBytes        -- Multitarget countermeasure for coins + contributory KEM
                          buf'     = BS.append bufP1Shaken bufPart2
                          kCoinsD  = shake256 buf' (3 * symBytes)
                      in BS.splitAt symBytes kCoinsD                 -- coins are in kCoinsD+NEWHOPE_SYMBYTES

    (coin1, coin2) = BS.splitAt symBytes coin12                      -- just the first symBytes part of buf

    ct = let seed = Internals.makeSeed coin1
             pt   = CPA_PKE.makePlainText bufP1Shaken
             pk'  = CPA_PKE.makePublicKeyFromBytes pkData
         in CPA_PKE.encrypt pt pk' seed

    ctData = let ctData' = CPA_PKE.getCTData ct
              in BS.append ctData' coin2                             -- copy Targhi-Unruh hash into ct

    coin1' = let n                = getPKn pk
                 cipherTextBytes' = cipherTextBytes n
             in shake256 (BS.take cipherTextBytes' ctData) symBytes  -- overwrite coins in kCoinsD with h(c)

    kCoinsD' = BS.append coin0 coin1'
    ss = shake256 kCoinsD' symBytes


-- | Called by the party initiating the protocol, this function
-- generates the 'SharedSecret' for the given 'CipherText' and
-- 'SecretKey'.  The result is the initiating party's copy of the
-- 'SecretKey'. (In terms of encryption functions per se, it is also a
-- cleartext value.)
decrypt :: CipherText -> SecretKey -> (Bool, SharedSecret)
decrypt ct sk = (success, ss)
-- NOTE: by selective use of the ! annotation and the
-- `constantTimeChoose` function, this routine tries to keep
-- computation time invariant between successful and unsuccessful
-- decryptions -- be careful about changing it. Note that we also have
-- automated tests that attempt to verify this property.
  where
    ctData = getCTData ct

    buf = let buf' = let publicText = CPA_PKE.decrypt (getCtCT ct) (getSkSecretKey sk)
                     in CPA_PKE.getPTData publicText
           in BS.append buf' $ getSkPkHash sk

    kCoinsD = shake256 buf (3 * symBytes)

    ctCmp = let coin2  = bsRange kCoinsD (2 * symBytes) symBytes
                ctCmp' = let seed = bsRange kCoinsD symBytes symBytes
                             bufp1 = BS.take symBytes buf
                         in CPA_PKE.encrypt (CPA_PKE.makePlainText bufp1) (getSkPkePublicKey sk) (Internals.makeSeed seed)
              in BS.append (CPA_PKE.getCTData ctCmp') coin2

    success = verify ctData ctCmp

    ssData = let firstTwoCoins = let kCoinsD'        = let coin1 = shake256 ctData symBytes
                                                       in bsReplace kCoinsD symBytes coin1    -- overwrite coins in kCoinsD with h(c)
                                     replacementCoin = let coin0 = BS.take symBytes kCoinsD'
                                                           z     = getSkZ sk
                                                       in constantTimeChoose success coin0 z  -- overwrite pre-k with z on re-encryption failure (possibly replace with cmov)
                                     kCoinsD''       = bsReplace kCoinsD' 0 replacementCoin
                                 in BS.take (2 * symBytes) kCoinsD''
             in shake256 firstTwoCoins symBytes                                               -- hash concatenation of pre-k and h(c) to k
    !ss = makeSharedSecret ssData

