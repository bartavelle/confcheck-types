{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE StrictData #-}
{-# LANGUAGE TemplateHaskell #-}

module Analysis.Types.Package where

import Control.Applicative
import Control.Lens
import Data.Aeson
import Data.Aeson.Types (typeMismatch)
import Data.Char (isAlpha, isDigit)
import qualified Data.Serialize as S
import Data.String
import Data.Text (Text)
import qualified Data.Text as T
import Data.Textual
import Elm.Derive
import GHC.Generics (Generic)
import qualified Text.Parser.Char as PC
import qualified Text.Printer as P

data VersionChunk
  = VNum Int
  | VLetter String
  deriving (Show, Eq, Generic)

instance ToJSON VersionChunk where
  toJSON (VNum x) = toJSON x
  toJSON (VLetter x) = toJSON x

instance FromJSON VersionChunk where
  parseJSON (String x) = return $ VLetter (T.unpack x)
  parseJSON (Number x) = return $ VNum (truncate x)
  parseJSON x = typeMismatch "VersionChunk" x

instance S.Serialize VersionChunk

instance Ord VersionChunk where
  compare (VNum a) (VNum b) = compare a b
  compare (VLetter a) (VLetter b) = compare a b
  compare (VLetter _) (VNum _) = LT
  compare (VNum _) (VLetter _) = GT

data RPMVersion
  = RPMVersion
      { getRPMVersion :: [VersionChunk],
        getRPMString :: String
      }
  deriving (Show, Eq, Ord, Generic)

instance S.Serialize RPMVersion

instance IsString RPMVersion where
  fromString = parseRPMVersion

parseRPMVersion :: String -> RPMVersion
parseRPMVersion v = RPMVersion (parseUndef (breakEl v)) v
  where
    breakEl [] = []
    breakEl ('.' : 'e' : 'l' : _) = []
    breakEl (x : xs) = x : breakEl xs
    parseUndef [] = []
    parseUndef (x : xs)
      | isDigit x = parseDigits [x] xs
      | isAlpha x = parseAlpha [x] xs
      | otherwise = parseUndef xs
    parseDigits curd [] = [VNum (read curd)]
    parseDigits curd (x : xs)
      | isDigit x = parseDigits (curd ++ [x]) xs
      | isAlpha x = VNum (read curd) : parseAlpha [x] xs
      | otherwise = VNum (read curd) : parseUndef xs
    parseAlpha curd [] = [VLetter curd]
    parseAlpha curd (x : xs)
      | isDigit x = VLetter curd : parseDigits [x] xs
      | isAlpha x = parseAlpha (curd ++ [x]) xs
      | otherwise = VLetter curd : parseUndef xs

instance Textual RPMVersion where
  textual = parseRPMVersion <$> some (PC.satisfy (const True))

instance Printable RPMVersion where
  print = P.text . descRPMVersion

descRPMVersion :: RPMVersion -> Text
descRPMVersion = T.pack . getRPMString

data PType
  = PRPM
  | PSolaris
  | PUnk
  | PDeb Text (Maybe Text) -- source, source version
  | WindowsDLL
  | WindowsInstall
  deriving (Show, Eq, Ord, Generic)

data SoftwarePackage
  = Package
      { _packageName :: Text,
        _packageVersion :: Text,
        _packageType :: PType
      }
  deriving (Show, Eq, Ord, Generic)

data SolarisPatch
  = SolarisPatch
      { _solPatchId :: Int,
        _solPatchRev :: Int
      }
  deriving (Show, Eq, Ord, Generic)

makeLenses ''SolarisPatch

$(deriveBoth (defaultOptionsDropLower 6) ''RPMVersion)

$(deriveBoth (defaultOptionsDropLower 0) ''PType)

$(deriveBoth (defaultOptionsDropLower 8) ''SoftwarePackage)

$(deriveBoth (defaultOptionsDropLower 9) ''SolarisPatch)

makeLenses ''SoftwarePackage
