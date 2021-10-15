{-# LANGUAGE OverloadedStrings #-}

module Data.Parsers.Helpers where

import Control.Applicative
import Data.String

englishMonth :: (Alternative m, IsString a, Eq a) => a -> m Int
englishMonth m = case m of
  "Jan" -> pure 1
  "Feb" -> pure 2
  "Mar" -> pure 3
  "Apr" -> pure 4
  "May" -> pure 5
  "Jun" -> pure 6
  "Jul" -> pure 7
  "Aug" -> pure 8
  "Sep" -> pure 9
  "Oct" -> pure 10
  "Nov" -> pure 11
  "Dec" -> pure 12
  _ -> empty
