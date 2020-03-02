{-# LANGUAGE DeriveGeneric   #-}
{-# LANGUAGE TemplateHaskell #-}
module Analysis.Types.Windows where

import           Control.Lens
import           Data.Bits
import qualified Data.ByteString         as BS
import qualified Data.HashMap.Strict     as HM
import           Data.Maybe              (mapMaybe)
import qualified Data.Set                as S
import           Data.Text               (Text)
import qualified Data.Thyme              as Y
import           Data.Thyme.Format.Aeson ()
import           Elm.Derive
import           GHC.Generics            (Generic)

import           Analysis.Types.Helpers  ()
import           Analysis.Windows.ACE
import           Analysis.Windows.SID

data WinGroup = WinGroup { _wingroupname     :: Text
                         , _wingroupsid      :: SID
                         , _wingroupcomments :: Maybe Text
                         , _wingroupmembers  :: [(Text, SID)]
                         } deriving (Show, Eq, Generic)

data UserAccountControlFlag = UAC_SCRIPT
                            | UAC_ACCOUNTDISABLE
                            | UAC_HOMEDIR_REQUIRED
                            | UAC_LOCKOUT
                            | UAC_PASSWD_NOTREQD
                            | UAC_PASSWD_CANT_CHANGE
                            | UAC_ENCRYPTED_TEXT_PWD_ALLOWED
                            | UAC_TEMP_DUPLICATE_ACCOUNT
                            | UAC_NORMAL_ACCOUNT
                            | UAC_INTERDOMAIN_TRUST_ACCOUNT
                            | UAC_WORKSTATION_TRUST_ACCOUNT
                            | UAC_SERVER_TRUST_ACCOUNT
                            | UAC_DONT_EXPIRE_PASSWORD
                            | UAC_MNS_LOGON_ACCOUNT
                            | UAC_SMARTCARD_REQUIRED
                            | UAC_TRUSTED_FOR_DELEGATION
                            | UAC_NOT_DELEGATED
                            | UAC_USE_DES_KEY_ONLY
                            | UAC_DONT_REQ_PREAUTH
                            | UAC_PASSWORD_EXPIRED
                            | UAC_TRUSTED_TO_AUTH_FOR_DELEGATION
                            | UAC_PARTIAL_SECRETS_ACCOUNT
                            deriving (Show, Eq, Ord, Generic, Enum, Bounded)

uacFlagValue :: Num a => UserAccountControlFlag -> a
uacFlagValue f = case f of
                     UAC_SCRIPT                         -> 0x1
                     UAC_ACCOUNTDISABLE                 -> 0x2
                     UAC_HOMEDIR_REQUIRED               -> 0x8
                     UAC_LOCKOUT                        -> 0x10
                     UAC_PASSWD_NOTREQD                 -> 0x20
                     UAC_PASSWD_CANT_CHANGE             -> 0x40
                     UAC_ENCRYPTED_TEXT_PWD_ALLOWED     -> 0x80
                     UAC_TEMP_DUPLICATE_ACCOUNT         -> 0x100
                     UAC_NORMAL_ACCOUNT                 -> 0x200
                     UAC_INTERDOMAIN_TRUST_ACCOUNT      -> 0x800
                     UAC_WORKSTATION_TRUST_ACCOUNT      -> 0x1000
                     UAC_SERVER_TRUST_ACCOUNT           -> 0x2000
                     UAC_DONT_EXPIRE_PASSWORD           -> 0x10000
                     UAC_MNS_LOGON_ACCOUNT              -> 0x20000
                     UAC_SMARTCARD_REQUIRED             -> 0x40000
                     UAC_TRUSTED_FOR_DELEGATION         -> 0x80000
                     UAC_NOT_DELEGATED                  -> 0x100000
                     UAC_USE_DES_KEY_ONLY               -> 0x200000
                     UAC_DONT_REQ_PREAUTH               -> 0x400000
                     UAC_PASSWORD_EXPIRED               -> 0x800000
                     UAC_TRUSTED_TO_AUTH_FOR_DELEGATION -> 0x1000000
                     UAC_PARTIAL_SECRETS_ACCOUNT        -> 0x4000000

decodeUACFlags :: (Num a, Bits a, Eq a) => a -> S.Set UserAccountControlFlag
decodeUACFlags n = S.fromList (mapMaybe check [minBound .. maxBound])
    where
        check flag = if n .&. uacFlagValue flag /= 0
                         then Just flag
                         else Nothing

data WinUser = WinUser { _winusername :: Text
                       , _winsid      :: SID
                       , _winflags    :: S.Set UserAccountControlFlag
                       , _wincomments :: Maybe Text
                       } deriving (Show, Eq, Generic)

data RegistryHive = HiveNamed Text
                  | HiveSID SID
                  deriving (Show, Eq, Generic)

data RegistryValue = RVDWord Int
                   | RVSZ Text
                   | RVMultiSZ Text
                   | RVBinary BS.ByteString
                   | RVExpand Text
                   deriving (Show, Eq, Generic)

data RegistryKey = RegistryKey { _regHive      :: RegistryHive
                               , _regName      :: Text
                               , _regLastWrite :: Y.UTCTime
                               , _regSD        :: SecurityDescriptor
                               , _regValues    :: HM.HashMap Text RegistryValue
                               } deriving (Show, Eq, Generic)

data WinLogonInfo = WinLogonInfo { _wliSID         :: SID
                                 , _wliNumLogon    :: Int
                                 , _wliPasswordAge :: Int
                                 , _wliLastLogon   :: Y.UTCTime
                                 } deriving (Show, Eq, Generic)

data WindowsService
    = WindowsService
    { _winsrvName    :: Text
    , _winsrvRunning :: Bool
    , _winsrvAutorun :: Bool
    , _winsrvUser    :: Text
    , _winsrvCmd     :: Text
    } deriving (Show, Eq, Generic)

$(deriveBoth ((defaultOptionsDropLower 4) { constructorTagModifier = drop 4 }) ''RegistryHive)
$(deriveBoth ((defaultOptionsDropLower 2) { constructorTagModifier = drop 2 }) ''RegistryValue)
$(deriveBoth ((defaultOptionsDropLower 4) { constructorTagModifier = drop 4 }) ''UserAccountControlFlag)
$(deriveBoth (defaultOptionsDropLower 4) ''RegistryKey)
$(deriveBoth (defaultOptionsDropLower 4) ''WinLogonInfo)
$(deriveBoth (defaultOptionsDropLower 9) ''WinGroup)
$(deriveBoth (defaultOptionsDropLower 4) ''WinUser)
$(deriveBoth (defaultOptionsDropLower 7) ''WindowsService)
makeLenses ''WinUser
