{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Analyzis.Windows.GUID where

import qualified Data.UUID as UUID
import Data.Textual
import Text.Printer (text)
import Control.Applicative
import Data.Char
import Data.Hashable

import qualified Text.Parser.Char as P

newtype GUID = GUID { _getGUID :: UUID.UUID }
               deriving (Eq, Ord, Hashable)

instance Printable GUID where
    print = text . UUID.toText . _getGUID

instance Textual GUID where
    textual = some (P.satisfy (\c -> isHexDigit c || c == '-'))
        >>= maybe empty (return . GUID) . UUID.fromString

instance Show GUID where
    show = toString

