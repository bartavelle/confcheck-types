{-# LANGUAGE RankNTypes   #-}
module Data.Parsers.Atto (englishMonthToInt) where

import qualified Data.ByteString.Char8 as BS
import           Data.String
import qualified Data.Text             as T
import           Prelude

englishMonthToInt :: (IsString a, Eq a) => a -> Maybe Int
{-# SPECIALIZE  englishMonthToInt :: T.Text -> Maybe Int #-}
{-# SPECIALIZE  englishMonthToInt :: BS.ByteString -> Maybe Int #-}
englishMonthToInt "Jan" = Just 1
englishMonthToInt "Feb" = Just 2
englishMonthToInt "Mar" = Just 3
englishMonthToInt "Apr" = Just 4
englishMonthToInt "May" = Just 5
englishMonthToInt "Jun" = Just 6
englishMonthToInt "Jul" = Just 7
englishMonthToInt "Aug" = Just 8
englishMonthToInt "Sep" = Just 9
englishMonthToInt "Oct" = Just 10
englishMonthToInt "Nov" = Just 11
englishMonthToInt "Dec" = Just 12
englishMonthToInt _     = Nothing

