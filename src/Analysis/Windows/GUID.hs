{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Analysis.Windows.GUID where

import Control.Applicative
import Data.Char
import Data.Hashable
import Data.Textual
import qualified Data.UUID as UUID
import qualified Text.Parser.Char as P
import Text.Printer (text)

newtype GUID = GUID {_getGUID :: UUID.UUID}
  deriving (Eq, Ord, Hashable)

instance Printable GUID where
  print = text . UUID.toText . _getGUID

instance Textual GUID where
  textual =
    some (P.satisfy (\c -> isHexDigit c || c == '-'))
      >>= maybe empty (return . GUID) . UUID.fromString

instance Show GUID where
  show = toString
