{-# LANGUAGE Safe #-}
{-|
  Module        : Crypto.NewHope.Internal.CPA_KEM
  Description   : IND-CPA-secure operations for the NewHope key exchange protocol
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

module Crypto.NewHope.Internal.CPA_KEM where


import           Control.DeepSeq
import qualified Data.ByteString as BS


import qualified Crypto.NewHope.CPA_PKE   as CPA_PKE
import           Crypto.NewHope.FIPS202
import           Crypto.NewHope.Internals (N (N1024, N512))
import qualified Crypto.NewHope.Internals as Internals
import           Crypto.NewHope.RNG


-- * Counting bytes

-- | Size of a PublicKey
publicKeyBytes :: Internals.N -> Int
publicKeyBytes = CPA_PKE.publicKeyBytes

-- | Size of a SecretKey
secretKeyBytes :: Internals.N -> Int
secretKeyBytes = CPA_PKE.secretKeyBytes

-- | Size of a CipherText
cipherTextBytes :: Internals.N -> Int
cipherTextBytes = CPA_PKE.cipherTextBytes


-- * PublicKey

-- | A public key; also the data sent from the first to the second
-- party in the key exchange.
newtype PublicKey = PublicKey BS.ByteString

-- | We need this instance so that we can deepseq this data for performance tests.
instance NFData PublicKey
  where
    rnf (PublicKey bs) = rnf bs


-- | Construct a PublicKey from a ByteString of exactly the right
-- size. The result will be a key of N512 or N1024 accordingly.
makePublicKey :: BS.ByteString -> PublicKey
makePublicKey pkData
    | not lengthOK = error "Invalid length for PublicKey"
    | otherwise    = PublicKey pkData
  where
    len      = BS.length pkData
    len512   = publicKeyBytes N512
    len1024  = publicKeyBytes N1024
    lengthOK = len == len512 || len == len1024


-- | The raw data inside the PublicKey
getPKData :: PublicKey -> BS.ByteString
getPKData (PublicKey pkData) = pkData


-- * SecretKey

-- | A secret key; used to derive initiating party's copy of the
-- 'SharedSecret' in combination with a 'CipherText' from the
-- responding party.
newtype SecretKey = SecretKey BS.ByteString

-- | We need this instance so that we can deepseq this data for performance tests.
instance NFData SecretKey
  where
    rnf (SecretKey bs) = rnf bs


-- | Construct a SecretKey from a ByteString of exactly the right
-- size. The result will be a key of N512 or N1024 accordingly.
makeSecretKey :: BS.ByteString -> SecretKey
makeSecretKey skData
    | not lengthOK = error "Invalid length for SecretKey"
    | otherwise    = SecretKey skData
  where
    len      = BS.length skData
    len512   = secretKeyBytes N512
    len1024  = secretKeyBytes N1024
    lengthOK = len == len512 || len == len1024

-- | The raw data inside the SecretKey
getSKData :: SecretKey -> BS.ByteString
getSKData (SecretKey skData) = skData


-- * CipherText

-- | Secret data sent from the responding party back to the initiating
-- party, used for initiating party to derive the 'SharedSecret'.
newtype CipherText = CipherText BS.ByteString

-- | We need this instance so that we can deepseq this data for performance tests.
instance NFData CipherText
  where
    rnf (CipherText bs) = rnf bs


-- | Construct a CipherText from a ByteString of exactly the right
-- size. The result will be of N512 or N1024, accordingly.
makeCipherText :: BS.ByteString -> CipherText
makeCipherText ctData
    | not lengthOK = error "Invalid length for CipherText"
    | otherwise    = CipherText ctData
  where
    len      = BS.length ctData
    len512   = cipherTextBytes N512
    len1024  = cipherTextBytes N1024
    lengthOK = len == len512 || len == len1024


-- | The raw data inside the CipherText
getCTData :: CipherText -> BS.ByteString
getCTData (CipherText ctData) = ctData


-- * SharedSecret

-- | The secret data posessed by both parties, resulting from the key
-- exchange protocol.
newtype SharedSecret = SharedSecret BS.ByteString deriving Eq

-- | We need this instance so that we can deepseq this data for performance tests.
instance NFData SharedSecret
  where
    rnf (SharedSecret bs) = rnf bs


-- | Construct a SharedSecret from a ByteString of length
-- 'sharedSecretBytes'.
makeSharedSecret :: BS.ByteString -> SharedSecret
makeSharedSecret pkData
    | not lengthOK = error "Invalid length for SharedSecret."
    | otherwise    = SharedSecret pkData
  where
    goodLength   = Internals.sharedSecretBytes
    actualLength = BS.length pkData
    lengthOK     = actualLength == goodLength

-- | The raw data inside the SharedSecret
getSSData :: SharedSecret -> BS.ByteString
getSSData (SharedSecret ssData) = ssData


-- * Top-level operations


-- | The first step of the NewHope key exchange protocol. Called by
-- the initiating party, generates 'PublicKey' and 'SecretKey'. The
-- 'PublicKey' is sent to the receiving party for the next step in the
-- protocol.
keypair :: Context -> Internals.N -> (PublicKey, SecretKey, Context)
keypair ctx n = (pk', sk', ctx')
  where
    -- Note that this encapsulates keys returned by CPA_PKE.
    (pk, sk, ctx') = CPA_PKE.keypair ctx n
    pk'            = makePublicKey $ CPA_PKE.getPKData pk
    sk'            = makeSecretKey $ CPA_PKE.getSKPolyData sk


-- | For the provided 'PublicKey', generates a 'CipherText' and
-- 'SharedSecret'.  Called by the receiving party, this produces that
-- party's version of the 'SharedSecret' and also the message to
-- transmit to the initiating party ('CipherText').
encrypt :: Context -> PublicKey -> (CipherText, SharedSecret, Context)
encrypt ctx pk = (ct, ss, ctx')
  where
    symBytes     = fromIntegral Internals.symBytes
    (buf, ctx')  = randomBytes ctx symBytes

    (buf0, buf1) = let buf_2sym = shake256 buf (2 * symBytes)
                   in BS.splitAt symBytes buf_2sym               -- we use them separately; coins are buf1 and buf0 used as cleartext

    ct = let ct' = let pk' = CPA_PKE.makePublicKeyFromBytes $ getPKData pk
                   in CPA_PKE.encrypt (CPA_PKE.makePlainText buf0) pk' (Internals.makeSeed buf1)
         in makeCipherText $ CPA_PKE.getCTData ct'

    ss = let ss' = shake256 buf0 symBytes                        -- hash pre-k to ss
         in makeSharedSecret ss'


-- | Called by the party initiating the protocol, this function
-- generates the 'SharedSecret' for the given 'CipherText' and
-- 'SecretKey'.  The result is the initiating party's copy of the
-- 'SecretKey'. (In terms of encryption functions per se, it is also a
-- cleartext value.)
decrypt :: CipherText -> SecretKey -> SharedSecret
decrypt ct sk = SharedSecret ss
  where
    ss = let ss'      = let ct' = CPA_PKE.makeCipherTextFromBytes $ getCTData ct
                            sk' = CPA_PKE.makeSecretKeyFromBytes $ getSKData sk
                        in CPA_PKE.decrypt ct' sk'
             symBytes = fromIntegral Internals.symBytes
          in shake256 (CPA_PKE.getPTData ss') symBytes -- hash pre-k to ss
