{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE Safe              #-}
{-|
  Module        : StringUtils
  Description   : String utilities for NewHope.
  Copyright     : © Jeremy Bornstein 2019
  License       : Apache 2.0
  Maintainer    : jeremy@bornstein.org
  Stability     : experimental
  Portability   : portable

  String utilities for NewHope.

-}

module StringUtils where

import qualified Data.ByteString            as BS
import           Data.ByteString.Builder
import qualified Data.ByteString.Char8      as BSC
import qualified Data.ByteString.Lazy       as BSL
import qualified Data.ByteString.Lazy.Char8 as BSLC
import           Numeric

import MiscUtils


-- | Pad a string to a given length
class Paddable a
  where
    pad :: Char -> Int -> a -> a

instance Paddable String
  where
    pad char len str = let
        remainder = mod (len - Prelude.length str) len
        extra = replicate remainder char
        in str ++ extra

instance Paddable BS.ByteString
  where
    pad char len str = let
        remainder = mod (len - BS.length str) len
        extra = replicate remainder char
        in str <> BSC.pack extra


-- | Convert from a readable hex representation to binary representation and vice-versa.
class HexStringable a where
  hexStringToByteString :: a -> BS.ByteString
  byteStringToHexString :: BS.ByteString -> a
  stringToHexString :: String -> a


instance HexStringable BS.ByteString where
  hexStringToByteString s = BSLC.toStrict . toLazyByteString $ builder
    where
      builder = foldr go (byteString BS.empty) $ BSC.unpack <$> chunk 2 s
      go a builder' = newbuilder <> builder'
        where
          newbuilder = word8 . fst . head . readHex . take 2 $ a

  byteStringToHexString = BSL.toStrict . toLazyByteString . byteStringHex
  stringToHexString = byteStringToHexString . BSC.pack


instance HexStringable BSL.ByteString where
  hexStringToByteString s = BSLC.toStrict . toLazyByteString $ builder
    where
      strict = BSL.toStrict s
      builder = foldr go (byteString BS.empty) $ BSC.unpack <$> chunk 2 strict
      go a builder' = newbuilder <> builder'
        where
          newbuilder = word8 . fst . head . readHex . take 2 $ a

  byteStringToHexString = toLazyByteString . byteStringHex
  stringToHexString = byteStringToHexString . BSC.pack


instance HexStringable String where

  hexStringToByteString s = BSL.toStrict . toLazyByteString $ builder
    where
      builder = foldr go (byteString BS.empty) $ chunk 2 s
      go a builder' = newbuilder <> builder'
        where
          newbuilder = word8 . fst . head . readHex . take 2 $ a

  byteStringToHexString = BSLC.unpack . toLazyByteString . byteStringHex
  stringToHexString = BSLC.unpack . toLazyByteString . byteStringHex . BSC.pack


-- | Extract a range of bytes from a ByteString
bsRange :: BS.ByteString -> Int -> Int -> BS.ByteString
bsRange source offset len = (BS.take len . BS.drop offset) source

-- | Compute a modification of input with a replacement overlaying the data at offset.
bsReplace :: BS.ByteString -> Int -> BS.ByteString -> BS.ByteString
bsReplace source offset new
    | BS.length result /= BS.length source = error errorMsg
    | otherwise = result
  where
    (initial, initialRest) = BS.splitAt offset source
    final = BS.drop (BS.length new) initialRest
    result = BS.append (BS.append initial new) final
    sourceLength = BS.length source
    newLength = BS.length new
    errorMsg = "Source length " ++ show sourceLength
               ++ "; replacement length: " ++ show newLength
               ++ " ...looks like source is shorter than required"  -- constants should prevent this
