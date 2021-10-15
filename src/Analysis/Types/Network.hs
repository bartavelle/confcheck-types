{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE StrictData #-}
{-# LANGUAGE TemplateHaskell #-}

module Analysis.Types.Network where

import Analysis.Types.Helpers ()
import Control.Lens
import Data.Aeson
import qualified Data.Foldable as F
import Data.List (intercalate)
import Data.Text (Text)
import Data.Textual
import Data.Vector (Vector)
import Data.Word
import Elm.Derive
import GHC.Generics (Generic)
import Network.IP.Addr
import qualified Text.Printer as P
import Text.Printf

data ConnectionState
  = LISTEN
  | ESTABLISHED {_remPort :: InetPort}
  | TIME_WAIT {_remPort :: InetPort}
  | LAST_ACK {_remPort :: InetPort}
  | CLOSE_WAIT {_remPort :: InetPort}
  | SYN_SENT {_remPort :: InetPort}
  | FIN_WAIT2 {_remPort :: InetPort}
  deriving (Show, Eq, Generic)

data IPProto
  = TCP
      { _locIP :: IP,
        _locPort :: InetPort,
        _remIP :: IP,
        _cnxstate :: ConnectionState
      }
  | UDP
      { _locIP :: IP,
        _locPort :: InetPort,
        _remIP :: IP,
        _cnxstate :: ConnectionState
      }
  deriving (Show, Eq, Generic)

data Connection
  = IP
      { _ipproto :: IPProto,
        _proginfo :: Maybe (Int, Text)
      }
  deriving (Show, Eq, Generic)

newtype MAC = MAC {getMac :: Vector Word8}
  deriving (Show, Eq, Ord, FromJSON, ToJSON)

instance Printable MAC where
  print = P.string7 . intercalate "." . map (printf "%02x") . F.toList . getMac

data NetIf
  = If4 {_ifname :: Text, _ifaddr4 :: Net4Addr, _ifmac :: Maybe MAC}
  | If6 {_ifname :: Text, _ifaddr6 :: Net6Addr, _ifmac :: Maybe MAC}
  deriving (Show, Eq, Generic)

makeLenses ''Connection

makeLenses ''NetIf

makeLenses ''IPProto

makeLenses ''ConnectionState

makePrisms ''ConnectionState

makePrisms ''IPProto

$(deriveBoth (defaultOptionsDropLower 4) ''ConnectionState)

$(deriveBoth (defaultOptionsDropLower 1) ''IPProto)

$(deriveBoth (defaultOptionsDropLower 1) ''Connection)

$(deriveBoth (defaultOptionsDropLower 3) ''NetIf)
