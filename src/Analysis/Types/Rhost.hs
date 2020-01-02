{-# LANGUAGE DeriveGeneric   #-}
{-# LANGUAGE TemplateHaskell #-}
module Analysis.Types.Rhost where

import           Control.Lens
import           Data.Text      (Text)
import           Elm.Derive
import           GHC.Generics   (Generic)

import           Data.Condition

data RHCond = RHHost Text
            | RHUser Text
            | RHHostGroup Text
            | RHUserGroup Text
            deriving (Show,Eq, Generic)

data Rhost = Rhost { _rhostSrc  :: Maybe Text -- ^ global, or for a specific user
                   , _rhostCond :: Condition RHCond
                   } deriving (Show, Eq, Generic)

makeLenses ''Rhost
$(deriveBoth (defaultOptionsDropLower 0) ''RHCond)
$(deriveBoth (defaultOptionsDropLower 6) ''Rhost)
