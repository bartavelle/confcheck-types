{-# LANGUAGE DeriveGeneric   #-}
{-# LANGUAGE StrictData      #-}
{-# LANGUAGE TemplateHaskell #-}
module Analysis.Types.Sudo where

import           Data.Text              (Text)
import           Elm.Derive
import           GHC.Generics           (Generic)
import           Network.IP.Addr

import           Analysis.Types.Helpers ()
import           Data.Condition
-- sudo stuff

data SudoUserId = SudoUsername  Text
                | SudoUid       Int
                | SudoGroupname Text
                | SudoGid       Int
                deriving (Show, Eq, Generic)

data SudoHostId = SudoHostname Text
                | SudoIP       IP
                | SudoNet4     Net4Addr
                | SudoNet6     Net6Addr
                deriving (Show, Eq, Generic)

data SudoCommand = Visudo
                 | SudoDirectory  Text
                 | SudoNoArgs     Text
                 | SudoAnyArgs    Text
                 | SudoArgs Text [Text]
                 deriving (Show, Eq, Generic)

data SudoPasswdSituation = SudoNoPassword
                         | SudoMyPassword
                         | SudoTargetPassword
                         deriving (Show, Eq, Generic)

data Sudo = Sudo { _sudoUser    :: Condition SudoUserId
                 , _sudoHost    :: Condition SudoHostId
                 , _sudoRunas   :: Condition SudoUserId
                 , _sudoPasswd  :: SudoPasswdSituation
                 , _sudoCommand :: Condition SudoCommand
                 , _sudoOrig    :: Text
                 } deriving (Show, Eq, Generic)

$(deriveBoth (defaultOptionsDropLower 0) ''SudoCommand)
$(deriveBoth (defaultOptionsDropLower 0) ''SudoUserId)
$(deriveBoth (defaultOptionsDropLower 0) ''SudoHostId)
$(deriveBoth (defaultOptionsDropLower 0) ''SudoPasswdSituation)
$(deriveBoth (defaultOptionsDropLower 5) ''Sudo)
