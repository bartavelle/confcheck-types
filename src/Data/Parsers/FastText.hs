{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DeriveFunctor #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE RankNTypes #-}

module Data.Parsers.FastText where

import Control.Applicative
import Control.Lens
import Data.AffineSpace ((.-^))
import Data.Char
import Data.Text (Text)
import Data.Text qualified as T
import Data.Thyme
import Text.Parser.Char qualified as P
import Text.Parser.Combinators qualified as P
import Text.Parser.Token qualified as P

newtype Parser a = Parser {runParser :: forall r. Text -> r -> (Text -> a -> r) -> r}
  deriving (Functor)

instance Applicative Parser where
  pure a = Parser $ \b _ s -> s b a
  {-# INLINE pure #-}
  Parser pf <*> Parser px = Parser $ \input failure success ->
    let succ' input' f = px input' failure (\i a -> success i (f a))
     in pf input failure succ'
  {-# INLINE (<*>) #-}

instance Alternative Parser where
  empty = Parser (\_ failure _ -> failure)
  {-# INLINE empty #-}
  Parser a <|> Parser b = Parser $ \input failure success -> a input (b input failure success) success
  {-# INLINE (<|>) #-}

instance Monad Parser where
  m >>= k = Parser $ \input failure success ->
    let succ' input' a = runParser (k a) input' failure success
     in runParser m input failure succ'
  {-# INLINE (>>=) #-}

instance MonadFail Parser where
  fail _ = Parser $ \_ failure _ -> failure

instance P.Parsing Parser where
  try = id
  (<?>) = const
  eof = Parser (\input failure success -> if T.null input then success input () else failure)
  unexpected _ = Parser (\_ failure _ -> failure)
  notFollowedBy (Parser p) = Parser (\input failure success -> p input (success input ()) (\_ _ -> failure))

instance P.CharParsing Parser where
  string s = Parser $ \input failure success -> case T.stripPrefix t input of
    Nothing -> failure
    Just r -> success r s
    where
      t = T.pack s
  text t = Parser $ \input failure success -> case T.stripPrefix t input of
    Nothing -> failure
    Just r -> success r t
  satisfy p = Parser pr
    where
      pr input failure success
        | T.null input = failure
        | p (T.head input) = success (T.tail input) (T.head input)
        | otherwise = failure

instance P.TokenParsing Parser

getInt :: Text -> Int
getInt = T.foldl' (\acc n -> acc * 10 + fromIntegral (digitToInt n)) 0
{-# INLINE getInt #-}

getOctal :: Text -> Int
getOctal = T.foldl' (\acc n -> acc * 8 + fromIntegral (digitToInt n)) 0
{-# INLINE getOctal #-}

decimal :: Parser Int
decimal = getInt <$> takeWhile1 isDigit
{-# INLINE decimal #-}

anyChar :: Parser Char
anyChar = Parser $ \input failure success -> if T.null input then failure else success (T.tail input) (T.head input)

char :: Char -> Parser ()
char c = Parser $ \input failure success -> if T.null input then failure else if T.head input == c then success (T.tail input) () else failure
{-# INLINE char #-}

scientific :: Parser Double
scientific = finalize . T.foldl' step (0, 0) <$> takeWhile1 (\n -> isDigit n || n == '.')
  where
    finalize :: (Int, Double) -> Double
    finalize (!n, !x) =
      if x == 0
        then fromIntegral n
        else fromIntegral n / x
    step (!n, !x) !v =
      if v == '.'
        then (n, 1)
        else (n * 10 + fromIntegral (digitToInt v), x * 10)
{-# INLINE scientific #-}

takeWhile1 :: (Char -> Bool) -> Parser Text
takeWhile1 prd = Parser $ \s failure success -> case T.span prd s of
  ("", _) -> failure
  (a, b) -> success b a
{-# INLINE takeWhile1 #-}

parseOnly :: Parser a -> Text -> Maybe a
parseOnly (Parser p) s = p s Nothing $ \b a ->
  if T.null b
    then Just a
    else Nothing

parseYMD :: Parser Day
parseYMD = do
  !y <- decimal <* char '-'
  !m <- decimal <* char '-'
  !d <- decimal
  return $! YearMonthDay y m d ^. from gregorian

parseDTime :: Parser DiffTime
parseDTime = do
  !h <- decimal <* char ':'
  !mi <- decimal <* char ':'
  !s <- scientific
  return $! fromSeconds $ fromIntegral (h * 3600 + mi * 60 :: Int) + s

timestamp :: Parser UTCTime
timestamp = do
  !day <- parseYMD <* char '+'
  !difftime <- parseDTime <* char '+'
  let !tm = UTCView day difftime ^. from utcTime
  !tz <- takeWhile1 isUpper
  return $! case tz of
    "CEST" -> tm .-^ fromSeconds (7200 :: Int)
    "CET" -> tm .-^ fromSeconds (3600 :: Int)
    _ -> tm

parseTimestamp :: Text -> Maybe UTCTime
parseTimestamp txt
  | "%++" `T.isPrefixOf` txt = Just $ view (from utcTime) $ UTCView (YearMonthDay 2016 03 12 ^. from gregorian) (fromSeconds (0 :: Int))
  | otherwise = parseOnly timestamp txt

pFold :: Parser a -> Fold Text a
pFold p = to (parseOnly p) . _Just
