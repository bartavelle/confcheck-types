{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE StrictData #-}
{-# LANGUAGE TemplateHaskell #-}

module Analysis.Types.Unix where

import Analysis.Types.Helpers ()
import Data.List (intercalate)
import Data.Serialize (Serialize (..))
import qualified Data.Text as T
import Data.Textual
import Elm.Derive
import GHC.Generics (Generic)
import qualified Text.Printer as P

data UnixType
  = RHEL
  | RedHatLinux
  | CentOS
  | SunOS
  | SuSE
  | OpenSuSE
  | Debian
  | Ubuntu
  | Unk T.Text
  | Fedora
  | OpenSUSELeap
  deriving (Eq, Ord, Show, Generic)

instance Printable UnixType where
  print = P.string . show

data UnixVersion = UnixVersion UnixType [Int]
  deriving (Show, Generic, Eq)

instance Printable UnixVersion where
  print (UnixVersion t v) = Data.Textual.print t <> " " <> P.string (intercalate "." (map show v))

instance Serialize UnixType

instance Serialize UnixVersion

$(deriveBoth (defaultOptionsDropLower 0) ''UnixType)

$(deriveBoth (defaultOptionsDropLower 0) ''UnixVersion)
