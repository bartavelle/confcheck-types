{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE StrictData #-}
{-# LANGUAGE TemplateHaskell #-}

module Analysis.Types.Rhost where

import Control.Lens
import Data.Condition
import Data.Text (Text)
import Elm.Derive
import GHC.Generics (Generic)

data RHCond
  = RHHost Text
  | RHUser Text
  | RHHostGroup Text
  | RHUserGroup Text
  deriving (Show, Eq, Generic)

data Rhost
  = Rhost
      { -- | global, or for a specific user
        _rhostSrc :: Maybe Text,
        _rhostCond :: Condition RHCond
      }
  deriving (Show, Eq, Generic)

makeLenses ''Rhost

$(deriveBoth (defaultOptionsDropLower 0) ''RHCond)

$(deriveBoth (defaultOptionsDropLower 6) ''Rhost)
