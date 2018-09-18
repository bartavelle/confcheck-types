{-# LANGUAGE Rank2Types #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveFunctor #-}
{-# LANGUAGE FlexibleContexts #-}
module Analysis.Common where

import Prelude
import qualified Data.Text as T
import qualified Data.Text.Read as T
import qualified Data.Text.Encoding as T
import qualified Data.ByteString as BS
import qualified Data.Attoparsec.Text as A
import Control.Lens
import Analysis.Types
import Control.Applicative
import Data.Maybe (fromMaybe,mapMaybe)
import qualified Data.Map.Strict as M
import qualified Data.Sequence as Seq
import Control.Concurrent
import Control.Monad
import Control.Monad.RSS.Strict
import Control.Monad.Trans.Except
import Data.List (isPrefixOf,isSuffixOf,isInfixOf)

import Control.Dependency

type Analyzer a = Require [T.Text] BS.ByteString a

data Pattern a = I a
               | P a
               | S a
               | E a
               deriving (Eq, Functor, Show)

class TextMatcher a where
    pPrefixOf :: a -> a -> Bool
    pSuffixOf :: a -> a -> Bool
    pInfixOf  :: a -> a -> Bool

instance Eq a => TextMatcher [a] where
    pPrefixOf = isPrefixOf
    pSuffixOf = isSuffixOf
    pInfixOf = isInfixOf

instance TextMatcher T.Text where
    pPrefixOf = T.isPrefixOf
    pSuffixOf = T.isSuffixOf
    pInfixOf = T.isInfixOf

instance TextMatcher BS.ByteString where
    pPrefixOf = BS.isPrefixOf
    pSuffixOf = BS.isSuffixOf
    pInfixOf = BS.isInfixOf

match :: (Eq a, TextMatcher a) => Pattern a -> a -> Bool
{-# SPECIALIZE match :: Pattern T.Text -> T.Text -> Bool #-}
{-# SPECIALIZE match :: Pattern BS.ByteString -> BS.ByteString -> Bool #-}
{-# SPECIALIZE match :: Pattern String -> String -> Bool #-}
match (P x) = pPrefixOf x
match (S x) = pSuffixOf x
match (I x) = pInfixOf x
match (E x) = (==) x

matchPattern :: (Eq a, TextMatcher a) => [Pattern a] -> a -> Bool
{-# SPECIALIZE matchPattern :: [Pattern T.Text] -> T.Text -> Bool #-}
{-# SPECIALIZE matchPattern :: [Pattern BS.ByteString] -> BS.ByteString -> Bool #-}
{-# SPECIALIZE matchPattern :: [Pattern String] -> String -> Bool #-}
matchPattern p f = any (`match` f) p

bs2txt :: Prism' BS.ByteString T.Text
bs2txt = prism' T.encodeUtf8 (preview (to T.decodeUtf8' . _Right))

filterTxt :: ([T.Text] -> Bool) -> Analyzer ([T.Text], T.Text)
filterTxt = fmap (_2 %~ safeBS2Text) . requireFilter

requireTxt :: [T.Text] -> Analyzer T.Text
requireTxt = fmap (safeBS2Text) . require

str2version :: T.Text -> Maybe UnixVersion
str2version "Red Hat Enterprise Linux 3" = Just (UnixVersion RHEL [3])
str2version "Red Hat Enterprise Linux 4" = Just (UnixVersion RHEL [4])
str2version "Red Hat Enterprise Linux 5" = Just (UnixVersion RHEL [5])
str2version x | "sles10-sp4" `T.isPrefixOf` x = Just (UnixVersion SuSE [10,4])
              | "sles10-sp3" `T.isPrefixOf` x = Just (UnixVersion SuSE [10,3])
              | "sles10-sp2" `T.isPrefixOf` x = Just (UnixVersion SuSE [10,2])
              | "sles10-sp1" `T.isPrefixOf` x = Just (UnixVersion SuSE [10,1])
              | "sles10" `T.isPrefixOf` x = Just (UnixVersion SuSE [10])
              | "sles11-sp3" `T.isPrefixOf` x = Just (UnixVersion SuSE [11,3])
              | "sles11-sp2" `T.isPrefixOf` x = Just (UnixVersion SuSE [11,2])
              | "sles11-sp1" `T.isPrefixOf` x = Just (UnixVersion SuSE [11,1])
              | "sles11" `T.isPrefixOf` x = Just (UnixVersion SuSE [11])
              | otherwise =   (T.stripPrefix "Red Hat Linux release " x >>= parseVersion RedHatLinux)
                          <|> (T.stripPrefix "Red Hat Enterprise Linux ES release " x >>= parseVersion RHEL)
                          <|> (T.stripPrefix "Red Hat Enterprise Linux " x >>= parseVersion RHEL)
                          <|> (T.stripPrefix "Red Hat Enterprise Linux Server release " x >>= parseVersion RHEL)
                          <|> (T.stripPrefix "openSUSE " x >>= parseVersion OpenSuSE)
                          <|> (T.stripPrefix "CentOS release " x >>= parseVersion RHEL)
                          <|> (T.stripPrefix "CentOS Linux release " x >>= parseVersion RHEL)
    where
        parseVersion c = either (const Nothing) (Just . UnixVersion c)
                            . A.parseOnly (A.decimal `A.sepBy1` A.char '.')

unixVersion :: Analyzer UnixVersion
unixVersion =   (redhat  <$> requireTxt ["conf/etc.tar.gz", "etc/redhat-release"])
            <|> (centos  <$> requireTxt ["conf/etc.tar.gz", "etc/centos-release"])
            <|> (suse    <$> requireTxt ["conf/etc.tar.gz", "etc/SuSE-release"])
            <|> (lsb     <$> requireTxt ["conf/etc.tar.gz", "etc/lsb-release"])
            <|> (debian  <$> requireTxt ["conf/etc.tar.gz", "etc/debian_version"])
            <|> (solaris <$> requireTxt ["conf/etc.tar.gz", "/etc/passwd"])
    where
        debian = UnixVersion Debian . fromMaybe [] . mapM text2Int . T.splitOn "." . T.strip
        redhat c = fromMaybe  (UnixVersion RHEL []) (str2version c)
        centos c = UnixVersion CentOS $ case str2version c of
                                            Just (UnixVersion _ v) -> v
                                            Nothing -> []
        suse x = fromMaybe (UnixVersion SuSE []) (suseversion x <|> str2version x)
        solaris = const (UnixVersion SunOS [])
        findKeys l = case map T.strip (T.splitOn "=" l) of
                         [t, n] -> Just (t, n)
                         _ -> Nothing
        lsb :: T.Text -> UnixVersion
        lsb = createVersion . M.fromList . mapMaybe findKeys . T.lines
          where
            extractRelease = mapM text2Int . T.split (=='.')
            createVersion m =
              case m ^? ix "DISTRIB_ID" of
                Just "Ubuntu" -> UnixVersion Ubuntu $ fromMaybe [] (m ^? ix "DISTRIB_RELEASE" >>= extractRelease)
                Just t -> UnixVersion (Unk t) []
                Nothing -> UnixVersion (Unk "check lsb code") []
        suseversion = createversion . M.fromList . mapMaybe findKeys . T.lines
          where
            createversion :: M.Map T.Text T.Text -> Maybe UnixVersion
            createversion m = (\a b -> UnixVersion SuSE [a,b]) <$> g m "VERSION" <*> g m "PATCHLEVEL"
            g m n = m ^? ix n >>= text2Int

newtype Once a = Once (MVar (Either (IO a) a))

mkOnce :: IO a -> IO (Once a)
mkOnce = fmap Once . newMVar . Left

getOnce :: Once a -> IO a
getOnce (Once o) = readMVar o >>= \x -> case x of
                                            Right v -> return v
                                            Left todo -> do
                                                a <- todo
                                                void (swapMVar o (Right a))
                                                return a

type PostAnalyzer = RSS (M.Map VulnGroup (Seq.Seq Vulnerability)) (Seq.Seq Vulnerability) ()
type FailAnalyzer = ExceptT Vulnerability PostAnalyzer

runPostAnalyzer :: M.Map VulnGroup (Seq.Seq Vulnerability) -> PostAnalyzer () -> Seq.Seq Vulnerability
runPostAnalyzer mp a = runRSS a mp () & view _3

tellVuln :: Vulnerability -> PostAnalyzer ()
tellVuln = tell . Seq.singleton

failVuln :: Vulnerability -> FailAnalyzer ()
failVuln = throwE

runFailAnalyzer :: FailAnalyzer () -> PostAnalyzer ()
runFailAnalyzer c = runExceptT c >>= \r -> case r of
                                               Right () -> return ()
                                               Left rr -> tellVuln rr

text2Int :: T.Text -> Maybe Int
text2Int = text2Integral

text2Integral :: Integral a => T.Text -> Maybe a
text2Integral t = case T.signed T.decimal t of
                      Right (x, "") -> Just x
                      _ -> Nothing

lineAnalyzer :: T.Text -> (T.Text -> Either String ConfigInfo) -> Analyzer (Seq.Seq ConfigInfo)
lineAnalyzer source linemanager = Seq.fromList . map run . T.lines <$> requireTxt [source]
    where
        run t = either (\s -> ConfigError (ParsingError source s (Just t))) id (linemanager t)
