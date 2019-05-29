{-# LANGUAGE OverloadedStrings #-}
module Main where

import Data.ByteString.Lazy (ByteString)
import qualified Data.ByteString.Lazy.Char8 as BS8
import qualified Data.HashMap.Strict as HM
import Control.Applicative
import Control.Monad

import Data.Parsers.Xml
import Test.Hspec

doc1 :: ByteString
doc1 = BS8.unlines
  [ "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
  , "<a attr1=\"lol\">"
  , "  <x1>yes</x1>"
  , "  <x1>no</x1>"
  , "  foo"
  , "  <x2 attr=\"lal\"></x2>"
  , "</a>"
  ]

shouldParse1 :: (Show a, Eq a) => Parser a -> a -> Expectation
shouldParse1 prs expected =
    case parseStream "dummy" doc1 prs of
      Left rr -> expectationFailure (show rr)
      Right x -> x `shouldBe` expected

shouldFail1 :: (Show a) => Parser a -> Expectation
shouldFail1 prs =
    case parseStream "dummy" doc1 prs of
      Left _ -> return ()
      Right x -> expectationFailure ("returned " ++ show x)

main :: IO ()
main = hspec $
  describe "doc1" $ do
    it "parses the xml header" $
      xml (pure ()) `shouldParse1` ()
    it "fails if elements are not ignored" $
      shouldFail1 $ xml (element "a" (pure . HM.lookup "attr1"))
    it "gets the first attribute, when ignoring all nested elements" $
      xml (element "a" (\mp -> HM.lookup "attr1" mp <$ ignoreNested [])) `shouldParse1` Just "lol"
    it "gets the first attribute, when ignoring specific elements" $
      let inner mp = HM.lookup "attr1" mp <$ do
            void $ many $ lx $ ignoreElement "x1"
            lx $ ignoreElement "x2"
      in  xml (element "a" inner) `shouldParse1` Just "lol"
    it "extracts text in x1" $
      let inner = do
            r <- many $ lx $ element_ "x1" characterdata
            lx $ ignoreElement "x2"
            pure r
      in  xml (element_ "a" inner) `shouldParse1` ["yes", "no"]

