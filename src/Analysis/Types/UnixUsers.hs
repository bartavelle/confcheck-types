{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE StrictData #-}
{-# LANGUAGE TemplateHaskell #-}

module Analysis.Types.UnixUsers where

import Analysis.Types.Rhost
import Analysis.Types.Sudo
import Control.Lens
import Data.Condition
import qualified Data.Map.Strict as M
import Data.Set (Set)
import Data.Text (Text)
import Elm.Derive
import GHC.Generics (Generic)

-- passwd / user data
data UnixUser
  = UnixUser
      { _uupwd :: PasswdEntry,
        _uushd :: Maybe ShadowEntry,
        _uugrp :: Maybe GroupEntry,
        _uuextra :: [GroupEntry],
        _uusudo :: M.Map Text (Condition SudoCommand),
        _uurhosts :: [Rhost]
      }
  deriving (Show, Eq, Generic)

dummyUser :: Text -> UnixUser
dummyUser n = UnixUser (PasswdEntry n "" 0 0 "" "" "") Nothing Nothing [] mempty mempty

data PasswdEntry
  = PasswdEntry
      { _pwdUsername :: Text,
        _pwdPass :: Text,
        _pwdUid :: Int,
        _pwdGid :: Int,
        _pwdGecos :: Text,
        _pwdHome :: Text,
        _pwdShell :: Text
      }
  deriving (Show, Eq, Generic)

data ShadowEntry
  = ShadowEntry
      { _shadowUsername :: Text,
        _shadowHash :: ShadowHash,
        _shadowLastchange :: Maybe Int,
        _shadowBeforechangeAllowed :: Maybe Int,
        _shadowBeforechangeRequired :: Maybe Int,
        _shadowWarning :: Maybe Int,
        _shadowBeforeinactive :: Maybe Int,
        _shadowExpires :: Maybe Int
      }
  deriving (Show, Eq, Generic)

data ShadowHash
  = SHash Text
  | SLocked
  | SNoPassword
  | SNotSetup
  deriving (Show, Eq, Generic)

data GroupEntry
  = GroupEntry
      { _groupName :: Text,
        _groupGid :: Int,
        _groupMembers :: Set Text
      }
  deriving (Show, Eq, Generic)

makeLenses ''UnixUser

makeLenses ''PasswdEntry

makeLenses ''GroupEntry

makeLenses ''ShadowEntry

makePrisms ''ShadowHash

$(deriveBoth (defaultOptionsDropLower 4) ''PasswdEntry)

$(deriveBoth (defaultOptionsDropLower 0) ''ShadowHash)

$(deriveBoth (defaultOptionsDropLower 7) ''ShadowEntry)

$(deriveBoth (defaultOptionsDropLower 6) ''GroupEntry)

$(deriveBoth (defaultOptionsDropLower 3) ''UnixUser)
