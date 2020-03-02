{-# LANGUAGE DeriveGeneric   #-}
{-# LANGUAGE TemplateHaskell #-}
module Analysis.Types.ConfigInfo where

import           Control.Lens
import qualified Data.ByteString          as BS
import           Data.Condition
import           Data.Sequence            (Seq)
import qualified Data.Sequence            as Seq
import qualified Data.Set                 as S
import           Data.Text                (Text)
import qualified Data.Text                as T
import qualified Data.Thyme               as Y
import           Data.Thyme.Format.Aeson  ()
import           Elm.Derive
import           GHC.Generics             (Generic)

import           Analysis.Types.Cron
import           Analysis.Types.File
import           Analysis.Types.Helpers
import           Analysis.Types.Network
import           Analysis.Types.Package
import           Analysis.Types.Rhost
import           Analysis.Types.Sudo
import           Analysis.Types.Unix
import           Analysis.Types.UnixUsers
import           Analysis.Types.Windows

data ConfigInfo = ConfPass        PasswdEntry
                | ConfShadow      ShadowEntry
                | ConfGroup       GroupEntry
                | SoftwarePackage SoftwarePackage
                | SolPatch        SolarisPatch
                | UVersion        UnixVersion
                | ConfigError     CError
                | Hostname        Text
                | ConfUnixUser    UnixUser
                | ConfWinUser     WinUser
                | ConfWinGroup    WinGroup
                | ConfWinLoginfo  WinLogonInfo
                | ConfUnixFile    BS.ByteString
                | ConfUnixFileNG  BS.ByteString
                | BrokenLink      UnixFile
                | CCronEntry      CronEntry
                | CConnection     Connection
                | CSudo           (Condition Sudo)
                | CIf             NetIf
                | CRhost          Rhost
                | KernelVersion   Text
                | Architecture    Text
                | MiscInfo        Text
                | Sysctl          Text Text -- key value
                | ValidShells     (S.Set Text)
                | AuditStart      Y.UTCTime
                | AuditEnd        Y.UTCTime
                | WinRegistry     RegistryKey
                | WinService      WindowsService
                deriving (Show, Eq, Generic)

parseToConfigInfo :: T.Text -> (a -> ConfigInfo) -> [Either String a] -> Seq.Seq ConfigInfo
parseToConfigInfo loc f = Seq.fromList . map tci
    where
        tci (Left rr) = ConfigError (ParsingError loc rr Nothing)
        tci (Right a) = f a

makePrisms ''ConfigInfo
$(deriveBoth (defaultOptionsDropLower 0) ''ConfigInfo)

extractVersion :: Seq ConfigInfo -> Maybe UnixVersion
extractVersion = preview (folded . _UVersion)

extractArch :: Seq ConfigInfo -> Maybe T.Text
extractArch = preview (folded . _Architecture)
