{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE Trustworthy       #-}
{-|
  Module        : ConfigFile
  Description   : Loads and parses configuration files for NewHope testing code
  Copyright     : © Jeremy Bornstein 2019
  License       : Apache 2.0
  Maintainer    : jeremy@bornstein.org
  Stability     : experimental
  Portability   : portable

-}

module ConfigFile where

import           Control.Applicative
import qualified Data.ByteString     as BS
import           Data.Map            (Map)
import qualified Data.Map            as M
import           Data.Maybe
import           Prelude             hiding (map)
import           Text.Trifecta


type Name = String
type Value = String
type Assignments = Map Name Value
newtype Header = Header String deriving (Eq, Ord, Show)
data Section = Section Header Assignments deriving (Eq, Show)
newtype Config = Config (Map Header Assignments) deriving (Eq, Show)


-- where our configuration files live
baseDirectory = "test/data/" -- ends with /
baseDirectory :: String


fromFile :: String -> IO Config
fromFile path = do let expandedPath = baseDirectory ++ path
                   fileContents <- BS.readFile expandedPath
                   let m = parseByteString parseIni mempty fileContents
                   case m of Success value -> return value
                             _             -> return $ Config M.empty


parseIni :: Parser Config
parseIni = do sections <- some parseSection
              let mapOfSections = foldr rollup M.empty sections
              return $ Config mapOfSections
  where
    rollup :: Section -> Map Header Assignments -> Map Header Assignments
    rollup (Section h a) = M.insert h a


parseHeader :: Parser Header
parseHeader = parseBracketPair (Header <$> sectionIdentifier)
  where
    parseBracketPair :: Parser a -> Parser a
    parseBracketPair p = char '[' *> p <* char ']'

    sectionIdentifier :: Parser String
    sectionIdentifier = do initial <- letter
                           middle <- some letterOrSpecialChar
                           return $ initial : middle
      where
        letterOrSpecialChar :: CharParsing m => m Char
        letterOrSpecialChar = char '_' <|> char '.' <|> alphaNum


skipEOL :: Parser ()
skipEOL = skipMany (oneOf "\n")


parseSection :: Parser Section
parseSection = do
    skipWhitespace
    skipComments
    h <- parseHeader
    skipEOL
    assignments <- some parseAssignment
    return $ Section h (M.fromList assignments)
  where
    skipWhitespace :: Parser ()
    skipWhitespace = skipMany (char ' ' <|> char '\n')


skipComments :: Parser ()
skipComments = skipMany (do _ <- char ';' <|> char '#'
                            skipMany (noneOf "\n")
                            skipEOL)


parseAssignment :: Parser (Name, Value)
parseAssignment = do name <- assignmentIdentifier
                     _ <- char '='
                     val <- some (noneOf "\n")
                     skipEOL
                     return (name, val)
  where
    assignmentIdentifier :: (Monad m, CharParsing m) => m String
    assignmentIdentifier = some $ char '_' <|> char '.' <|> alphaNum



sectionNames :: Config -> [String]
sectionNames (Config map) = [go header | header <- M.keys map]
  where
    go (Header name) = name


sectionNamed :: Config -> String -> Assignments
sectionNamed (Config map) name = result -- map M.!? Header name
  where
    existing = map M.!? Header name
    result = if isNothing existing
             then M.empty
             else let (Just innerResult) = existing
                  in innerResult


-- * Testing Utilities
-- The following functions are used by testing code once their files
-- have been loaded.


parseListWordIntegral :: Integral a => Parser [a]
parseListWordIntegral = do _ <- char '['
                           result <- some parseIntAndMaybeComma
                           _ <- char ']'
                           return result


toIntegralList :: (Enum a, Integral b) => [a] -> [b]
toIntegralList = fmap (fromIntegral . fromEnum)


parseListIntegralPairs :: (Integral a, Integral b) => Parser [(a, b)]
parseListIntegralPairs = do _ <- char '['
                            value <- some parsePairAndMaybeComma
                            _ <- char ']'
                            return value
  where
    parsePairAndMaybeComma :: (Integral a, Integral b) => Parser (a, b)
    parsePairAndMaybeComma = do
      _ <- char '('
      value <- integer
      _ <- char ','
      value' <- integer
      _ <- char ')'
      _ <- option 'x' $ char ','
      return (fromIntegral value, fromIntegral value')


parseListIntegralMap :: (Integral a, Integral b) => Parser [(a, [b])]
parseListIntegralMap = do _ <- char '['
                          item <- some parsePairAndMaybeComma
                          _ <- char ']'
                          return item
  where
    parsePairAndMaybeComma :: (Integral a, Integral b) => Parser (a, [b])
    parsePairAndMaybeComma = do _ <- char '('
                                key <- integer
                                _ <- char ','
                                _ <- char '['
                                values <- some parseIntAndMaybeComma
                                _ <- char ']'
                                _ <- char ')'
                                _ <- option 'x' $ char ','
                                return (fromIntegral key, values)


parseIntAndMaybeComma :: Integral a => Parser a
parseIntAndMaybeComma = do value <- integer
                           _ <- option 'x' $ char ','
                           return $ fromIntegral value
