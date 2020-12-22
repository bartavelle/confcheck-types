{-# LANGUAGE DeriveGeneric              #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE StrictData                 #-}
{-# LANGUAGE TemplateHaskell            #-}
module Analysis.Types.File where

import           Control.Lens
import           Data.Aeson
import           Data.Bits
import           Data.Bits.Lens
import           Data.Text               (Text)
import qualified Data.Thyme              as Y
import           Data.Thyme.Format.Aeson ()
import           Elm.Derive
import           GHC.Generics            (Generic)

-- files
data FileType
    = TFile
    | TDirectory
    | TLink
    | TPipe
    | TSocket
    | TBlock
    | TChar
    | TDoor
    deriving (Eq, Show, Generic)

newtype FPerms = FPerms { getFPerms :: Int }
               deriving (Show, Ord, Eq, Num, Bits, ToJSON, FromJSON)

data UnixFileGen usertpe pathtype
    = UnixFileGen
    { _fileInode     :: !Int
    , _fileHardLinks :: !Int
    , _fileAtime     :: !Y.UTCTime
    , _fileMtime     :: !Y.UTCTime
    , _fileCtime     :: !Y.UTCTime
    , _fileUser      :: !usertpe
    , _fileGroup     :: !usertpe
    , _fileBlocks    :: !Int
    , _fileType      :: !FileType
    , _filePerms     :: !FPerms
    , _fileSize      :: !Int
    , _filePath      :: !pathtype
    , _fileTarget    :: !(Maybe pathtype)
    } deriving (Show, Eq, Generic)

instance Bifunctor UnixFileGen where
    bimap f g (UnixFileGen i h a m c u gr b t p s pat tgt) = UnixFileGen i h a m c (f u) (f gr) b t p s (g pat) (fmap g tgt)

type UnixFile = UnixFileGen Text FilePath

permsOR :: Lens' FPerms Bool
permsOR = bitAt 2
permsOW :: Lens' FPerms Bool
permsOW = bitAt 1
permsOX :: Lens' FPerms Bool
permsOX = bitAt 0
permsGR :: Lens' FPerms Bool
permsGR = bitAt 5
permsGW :: Lens' FPerms Bool
permsGW = bitAt 4
permsGX :: Lens' FPerms Bool
permsGX = bitAt 3
permsUR :: Lens' FPerms Bool
permsUR = bitAt 8
permsUW :: Lens' FPerms Bool
permsUW = bitAt 7
permsUX :: Lens' FPerms Bool
permsUX = bitAt 6
permsST :: Lens' FPerms Bool
permsST = bitAt 11
permsSG :: Lens' FPerms Bool
permsSG = bitAt 10
permsSU :: Lens' FPerms Bool
permsSU = bitAt 9

filetype2char :: FileType -> Char
filetype2char TFile      = 'f'
filetype2char TDirectory = 'd'
filetype2char TLink      = 'l'
filetype2char TPipe      = 'p'
filetype2char TSocket    = 's'
filetype2char TBlock     = 'b'
filetype2char TChar      = 'c'
filetype2char TDoor      = 'D'

makeLenses ''UnixFileGen
$(deriveBoth (defaultOptionsDropLower 0) ''FileType)
$(deriveBoth (defaultOptionsDropLower 5) ''UnixFileGen)
