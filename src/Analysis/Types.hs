{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE DeriveFoldable             #-}
{-# LANGUAGE DeriveFunctor              #-}
{-# LANGUAGE DeriveGeneric              #-}
{-# LANGUAGE DeriveTraversable          #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE RankNTypes                 #-}
{-# LANGUAGE TemplateHaskell            #-}
module Analysis.Types
    ( module Analysis.Types
    , module Analysis.Windows.SID
    ) where

import           Control.Applicative
import           Control.Comonad
import           Control.DeepSeq
import           Control.Lens            hiding ((.=))
import           Data.Aeson
import           Data.Aeson.Types
import qualified Data.Aeson.Types        as A
import           Data.Attoparsec.Text    (parseOnly)
import           Data.Bits
import           Data.Bits.Lens
import qualified Data.ByteString         as BS
import           Data.Char               (isAlpha, isDigit)
import           Data.Condition
import qualified Data.Foldable           as F
import qualified Data.HashMap.Strict     as HM
import           Data.List               (intercalate)
import qualified Data.Map.Strict         as M
import           Data.Maybe              (mapMaybe)
import           Data.Sequence           (Seq)
import qualified Data.Sequence           as Seq
import           Data.Serialize          (Serialize (..))
import qualified Data.Serialize          as S
import           Data.Set                (Set)
import qualified Data.Set                as S
import           Data.String
import           Data.Text               (Text)
import qualified Data.Text               as T
import qualified Data.Text.Encoding      as T
import           Data.Textual
import qualified Data.Thyme              as Y
import           Data.Thyme.Format.Aeson ()
import           Data.Time               (Day, fromGregorian, toGregorian)
import           Data.Vector             (Vector)
import           Data.Word
import           Elm.Derive
import           GHC.Generics            hiding (to)
import           Network.IP.Addr
import           Prelude
import qualified Text.Parser.Char        as PC
import qualified Text.Printer            as P
import           Text.Printf

import           Analysis.Windows.ACE
import           Analysis.Windows.SID

-- orphan instances and other hacks :(

instance Serialize Day where
        put = put . toGregorian
        get = fmap (\(y,m,d) -> fromGregorian y m d) get

instance Serialize Text where
        put = put . T.encodeUtf8
        get = fmap T.decodeUtf8 get

safeBS2Text :: BS.ByteString -> Text
safeBS2Text t = case T.decodeUtf8' t of
                    Right v -> v
                    Left _  -> T.decodeLatin1 t

instance FromJSON BS.ByteString where
    parseJSON (String s) = pure $ T.encodeUtf8 s
    parseJSON _          = fail "Could not parse ByteString"

instance ToJSON BS.ByteString where
    toJSON b = String (safeBS2Text b)

-- DB types

data AuditFileType = AuditTar
                   | AuditTarGz
                   | MBSAReport
                   | WinVBSReport
                   | MissingKBs
                   | WinAuditTool
                   deriving (Eq, Ord, Enum, Generic, Show)

-- severity
data Severity = None
              | Unknown
              | Low
              | Medium
              | High
              | CVSS Double
              deriving (Eq, Show, Generic)

instance NFData Severity

tocvss :: Severity -> Double
tocvss Unknown  = -1
tocvss None     = 0
tocvss Low      = 2
tocvss Medium   = 5
tocvss High     = 8
tocvss (CVSS x) = x

fromCVSS :: Double -> Severity
fromCVSS x | x < 0 = Unknown
           | x == 0 = None
           | x < 3 = Low
           | x < 7 = Medium
           | otherwise = High

instance Ord Severity where
    compare None Unknown = LT
    compare Unknown None = GT
    compare a b          = compare (tocvss a) (tocvss b)

instance Serialize Severity where

instance Semigroup Severity where
    (<>) = max

instance Monoid Severity where
    mempty = Unknown

-- files
data FileType = TFile
              | TDirectory
              | TLink
              | TPipe
              | TSocket
              | TBlock
              | TChar
              | TDoor
              deriving (Eq, Show, Generic)

newtype FPerms = FPerms { getFPerms :: Int }
               deriving (Show, Ord, Eq, Num, Bits, ToJSON, FromJSON)

data UnixFileGen usertpe pathtype = UnixFileGen { _fileInode     :: !Int
                                                , _fileHardLinks :: !Int
                                                , _fileAtime     :: !Y.UTCTime
                                                , _fileMtime     :: !Y.UTCTime
                                                , _fileCtime     :: !Y.UTCTime
                                                , _fileUser      :: !usertpe
                                                , _fileGroup     :: !usertpe
                                                , _fileBlocks    :: !Int
                                                , _fileType      :: !FileType
                                                , _filePerms     :: !FPerms
                                                , _fileSize      :: !Int
                                                , _filePath      :: !pathtype
                                                , _fileTarget    :: !(Maybe pathtype)
                                                } deriving (Show, Eq, Generic)

instance Bifunctor UnixFileGen where
    bimap f g (UnixFileGen i h a m c u gr b t p s pat tgt) = UnixFileGen i h a m c (f u) (f gr) b t p s (g pat) (fmap g tgt)

type UnixFile = UnixFileGen Text FilePath

-- rhost stuff

data RHCond = RHHost Text
            | RHUser Text
            | RHHostGroup Text
            | RHUserGroup Text
            deriving (Show,Eq, Generic)

data Rhost = Rhost { _rhostSrc  :: Maybe Text -- ^ global, or for a specific user
                   , _rhostCond :: Condition RHCond
                   } deriving (Show, Eq, Generic)

-- passwd / user data
data UnixUser = UnixUser { _uupwd    :: PasswdEntry
                         , _uushd    :: Maybe ShadowEntry
                         , _uugrp    :: Maybe GroupEntry
                         , _uuextra  :: [GroupEntry]
                         , _uusudo   :: M.Map Text (Condition SudoCommand)
                         , _uurhosts :: [Rhost]
                         } deriving (Show, Eq, Generic)

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

dummyUser :: Text -> UnixUser
dummyUser n = UnixUser (PasswdEntry n "" 0 0 "" "" "") Nothing Nothing [] mempty mempty

data PasswdEntry = PasswdEntry { _pwdUsername :: Text
                               , _pwdPass     :: Text
                               , _pwdUid      :: Int
                               , _pwdGid      :: Int
                               , _pwdGecos    :: Text
                               , _pwdHome     :: Text
                               , _pwdShell    :: Text
                               } deriving (Show, Eq, Generic)

data ShadowEntry = ShadowEntry { _shadowUsername             :: Text
                               , _shadowHash                 :: ShadowHash
                               , _shadowLastchange           :: Maybe Int
                               , _shadowBeforechangeAllowed  :: Maybe Int
                               , _shadowBeforechangeRequired :: Maybe Int
                               , _shadowWarning              :: Maybe Int
                               , _shadowBeforeinactive       :: Maybe Int
                               , _shadowExpires              :: Maybe Int
                               } deriving (Show, Eq, Generic)

data ShadowHash = SHash Text
                | SLocked
                | SNoPassword
                | SNotSetup
                deriving (Show, Eq, Generic)

data GroupEntry = GroupEntry { _groupName    :: Text
                             , _groupGid     :: Int
                             , _groupMembers :: Set Text
                             } deriving (Show, Eq, Generic)

-- package data


data VersionChunk = VNum Int
                  | VLetter String
                  deriving (Show, Eq, Generic)

instance ToJSON VersionChunk where
    toJSON (VNum x)    = toJSON x
    toJSON (VLetter x) = toJSON x

instance FromJSON VersionChunk where
    parseJSON (String x) = return $ VLetter (T.unpack x)
    parseJSON (Number x) = return $ VNum (truncate x)
    parseJSON x          = typeMismatch "VersionChunk" x

instance S.Serialize VersionChunk where

instance Ord VersionChunk where
    compare (VNum a)    (VNum b)    = compare a b
    compare (VLetter a) (VLetter b) = compare a b
    compare (VLetter _) (VNum _)    = LT
    compare (VNum _)    (VLetter _) = GT

data RPMVersion = RPMVersion { getRPMVersion :: [VersionChunk]
                             , getRPMString  :: String }
                   deriving (Show, Eq, Ord, Generic)

instance S.Serialize RPMVersion where

instance IsString RPMVersion where
    fromString = parseRPMVersion

parseRPMVersion :: String -> RPMVersion
parseRPMVersion v = RPMVersion (parseUndef (breakEl v)) v
    where
        breakEl []                    = []
        breakEl ('.' : 'e' : 'l' : _) = []
        breakEl (x:xs)                = x : breakEl xs
        parseUndef [] = []
        parseUndef (x:xs) | isDigit x = parseDigits [x] xs
                          | isAlpha x = parseAlpha [x] xs
                          | otherwise = parseUndef xs
        parseDigits curd [] = [VNum (read curd)]
        parseDigits curd (x:xs) | isDigit x = parseDigits (curd ++ [x]) xs
                                | isAlpha x = VNum (read curd) : parseAlpha [x] xs
                                | otherwise = VNum (read curd) : parseUndef xs
        parseAlpha curd [] = [VLetter curd]
        parseAlpha curd (x:xs) | isDigit x = VLetter curd : parseDigits [x] xs
                               | isAlpha x = parseAlpha (curd ++ [x]) xs
                               | otherwise = VLetter curd : parseUndef xs

instance Textual RPMVersion where
    textual = parseRPMVersion <$> some (PC.satisfy (const True))

instance Printable RPMVersion where
    print = P.text . descRPMVersion

descRPMVersion :: RPMVersion -> Text
descRPMVersion = T.pack . getRPMString

data PType = PRPM
           | PSolaris
           | PUnk
           | PDeb Text (Maybe Text) -- source, source version
           | WindowsDLL
           | WindowsInstall
           deriving (Show, Eq, Ord, Generic)

data SoftwarePackage = Package { _packageName    :: Text
                               , _packageVersion :: Text
                               , _packageType    :: PType
                               } deriving (Show, Eq, Ord, Generic)

data SolarisPatch = SolarisPatch { _solPatchId  :: Int
                                 , _solPatchRev :: Int
                                 } deriving (Show, Eq, Ord, Generic)

-- unix versions
data UnixType = RHEL
              | RedHatLinux
              | CentOS
              | SunOS
              | SuSE
              | OpenSuSE
              | Debian
              | Ubuntu
              | Unk T.Text
              | WindowsClient T.Text
              | WindowsServer T.Text
              deriving (Eq, Ord, Show, Generic)

instance Printable UnixType where
    print = P.string . show

data UnixVersion = UnixVersion UnixType [Int]
                 deriving (Show, Generic, Eq)

instance Printable UnixVersion where
    print (UnixVersion t v) = Data.Textual.print t <> " " <> P.string (intercalate "." (map show v))

instance Serialize UnixType where
instance Serialize UnixVersion where

-- some error type
data CError = MiscError Text
            | ParsingError Text String (Maybe Text) -- source name, error, original line
            deriving (Show, Eq, Generic)

-- crons

data CronSchedule = CronYearly
                  | CronMonthly
                  | CronWeekly
                  | CronDaily
                  | CronReboot
                  | CronHourly
                  | CronSchedule Text Text Text Text Text
                  deriving (Show,Eq, Generic)

data CronEntry = CronEntry { _cronUser              :: Text
                           , _cronSchedule          :: CronSchedule
                           , _cronCommand           :: Text
                           , _cronExtractedCommands :: [FilePath]
                           } deriving (Show, Eq, Generic)

-- network stuff

data ConnectionState = LISTEN
                     | ESTABLISHED { _remPort :: InetPort }
                     | TIME_WAIT   { _remPort :: InetPort }
                     | LAST_ACK    { _remPort :: InetPort }
                     | CLOSE_WAIT  { _remPort :: InetPort }
                     | SYN_SENT    { _remPort :: InetPort }
                     | FIN_WAIT2   { _remPort :: InetPort }
                     deriving (Show, Eq, Generic)

data IPProto = TCP { _locIP    :: IP
                   , _locPort  :: InetPort
                   , _remIP    :: IP
                   , _cnxstate :: ConnectionState
                   }
             | UDP { _locIP    :: IP
                   , _locPort  :: InetPort
                   , _remIP    :: IP
                   , _cnxstate :: ConnectionState
                   }
                   deriving (Show, Eq, Generic)

data Connection = IP { _ipproto  :: IPProto
                     , _proginfo ::  Maybe (Int, Text)
                     }
                deriving (Show, Eq, Generic)

newtype MAC = MAC { getMac :: Vector Word8 }
            deriving (Show, Eq, Ord, FromJSON, ToJSON)

instance Printable MAC where
    print = P.string7 . intercalate "." . map (printf "%02x") . F.toList . getMac

data NetIf = If4 { _ifname :: Text, _ifaddr4 :: Net4Addr, _ifmac :: Maybe MAC }
           | If6 { _ifname :: Text, _ifaddr6 :: Net6Addr, _ifmac :: Maybe MAC }
           deriving (Show, Eq, Generic)

-- the negatable type, for things that can be negated :)

data Negatable a = Positive a
                 | Negative a
                 deriving (Show, Eq, Functor, F.Foldable, Traversable, Generic)

instance Comonad Negatable where
    extract (Positive x) = x
    extract (Negative x) = x
    duplicate (Positive x) = Positive (Positive x)
    duplicate (Negative x) = Negative (Negative x)
    extend f x@(Positive _) = Positive $ f x
    extend f x@(Negative _) = Negative $ f x

negatableToCondition :: Negatable a -> Condition a
negatableToCondition (Positive x) = Pure x
negatableToCondition (Negative x) = Not (Pure x)

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

-- main config info type
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
                deriving (Show, Eq, Generic)

parseToConfigInfo :: T.Text -> (a -> ConfigInfo) -> [Either String a] -> Seq.Seq ConfigInfo
parseToConfigInfo loc f = Seq.fromList . map tci
    where
        tci (Left rr) = ConfigError (ParsingError loc rr Nothing)
        tci (Right a) = f a

-- vulnerability list
data Vulnerability = Vulnerability !Severity !VulnType
                   | ConfigInformation !ConfigInfo
                   | SomethingToCheck
                   deriving (Show, Eq, Generic)

instance Ord Vulnerability where
    compare (Vulnerability sa va) (Vulnerability sb vb) = compare sa sb <> compare va vb
    compare (Vulnerability _ _) _ = GT
    compare _ (Vulnerability _ _) = LT
    compare (ConfigInformation _) (ConfigInformation _) = EQ
    compare (ConfigInformation _) _ = LT
    compare _ (ConfigInformation _) = GT
    compare SomethingToCheck SomethingToCheck = EQ


data VulnType = OutdatedPackage Text -- human readable title
                                Text -- installed version
                                Text -- patch version
                                Day  -- patch publication
                                (Maybe Text) -- various data
              | MissingPatch Text -- patch identifier
                             Day  -- patch publication
                             (Maybe Text) -- patch description
              | MultipleUser Text -- description of the field that is multiple
                             [PasswdEntry]
              | MultipleGroup Text -- description of the field that is multiple
                              [GroupEntry]
              | MultipleShadow Text -- description of the field that is multiple
                              [ShadowEntry]
              | VRhost Rhost
              | VFile FileVuln
              | MiscVuln Text
              | WrongSysctl { _sysctlKey :: Text, _sysctlActual :: Text, _sysctlExpected :: Text, _sysctrlDesc :: Maybe Text }
              deriving (Show, Eq, Generic)

data FileVuln = ShouldNotBeWritable               { _vtReason :: Text, _vtFile :: UnixFile }
              | ShouldNotBeReadable               { _vtReason :: Text, _vtFile :: UnixFile }
              | ShouldBeOwnedBy { _vtOwner :: Text, _vtReason :: Text, _vtFile :: UnixFile }
              | StrangeSuid UnixFile
              deriving (Show, Eq, Generic)

instance Ord VulnType where
    compare a b = compare (td b) (td a)
        where
            td (OutdatedPackage _ _ _ d _) = d
            td (MissingPatch _ d _)        = d
            td _                           = fromGregorian 1970 1 1

fromJsonTextual :: Textual a => A.Value -> A.Parser a
fromJsonTextual = withText "string" $ \x -> case parseOnly textual x of
                                                Right r -> return r
                                                Left rr -> fail rr

instance FromJSON IP4           where parseJSON = fromJsonTextual
instance FromJSON IP6           where parseJSON = fromJsonTextual
instance FromJSON IP            where parseJSON = fromJsonTextual
instance FromJSON (NetAddr IP4) where parseJSON = fromJsonTextual
instance FromJSON (NetAddr IP6) where parseJSON = fromJsonTextual
instance ToJSON   IP4           where toJSON = String . toText
instance ToJSON   IP6           where toJSON = String . toText
instance ToJSON   IP            where toJSON = String . toText
instance ToJSON (NetAddr IP4)   where toJSON = String . toText
instance ToJSON (NetAddr IP6)   where toJSON = String . toText

instance FromJSON InetPort where
    parseJSON (Number n) = pure (fromIntegral (truncate n :: Int))
    parseJSON _          = fail "Could not parse port number"

instance ToJSON InetPort where
    toJSON = Number . fromIntegral

makeLenses ''Rhost
makeLenses ''Connection
makeLenses ''NetIf
makeLenses ''UnixUser
makeLenses ''WinUser
makeLenses ''IPProto
makeLenses ''ConnectionState
makeLenses ''PasswdEntry
makeLenses ''GroupEntry
makeLenses ''ShadowEntry
makeLenses ''SolarisPatch
makeLenses ''SoftwarePackage
makeLenses ''UnixFileGen
makeLenses ''VulnType
makeLenses ''FileVuln
makePrisms ''ConfigInfo
makePrisms ''Vulnerability
makePrisms ''VulnType
makePrisms ''FileVuln
makePrisms ''IPProto
makePrisms ''ConnectionState
makePrisms ''ShadowHash

permsOR :: Lens' FPerms Bool
permsOR = bitAt 2
permsOW :: Lens' FPerms Bool
permsOW = bitAt 1
permsOX :: Lens' FPerms Bool
permsOX = bitAt 0
permsGR :: Lens' FPerms Bool
permsGR = bitAt 5
permsGW :: Lens' FPerms Bool
permsGW = bitAt 4
permsGX :: Lens' FPerms Bool
permsGX = bitAt 3
permsUR :: Lens' FPerms Bool
permsUR = bitAt 8
permsUW :: Lens' FPerms Bool
permsUW = bitAt 7
permsUX :: Lens' FPerms Bool
permsUX = bitAt 6
permsST :: Lens' FPerms Bool
permsST = bitAt 11
permsSG :: Lens' FPerms Bool
permsSG = bitAt 10
permsSU :: Lens' FPerms Bool
permsSU = bitAt 9

filetype2char :: FileType -> Char
filetype2char TFile      = 'f'
filetype2char TDirectory = 'd'
filetype2char TLink      = 'l'
filetype2char TPipe      = 'p'
filetype2char TSocket    = 's'
filetype2char TBlock     = 'b'
filetype2char TChar      = 'c'
filetype2char TDoor      = 'D'

extractVersion :: Seq ConfigInfo -> Maybe UnixVersion
extractVersion = preview (folded . _UVersion)

extractArch :: Seq ConfigInfo -> Maybe T.Text
extractArch = preview (folded . _Architecture)

data VulnGroup = GErrors
               | GPackages
               | GAuthUnix
               | GAuthWin
               | GFS
               | GCron
               | GNet
               | GInfo
               | GMisc
               deriving (Ord, Eq)

_VulnGroup :: Prism' Text VulnGroup
_VulnGroup = prism' vg2txt parsevg
    where
        vg2txt GMisc     = "misc"
        vg2txt GFS       = "filesystem"
        vg2txt GErrors   = "errors"
        vg2txt GPackages = "packages"
        vg2txt GAuthWin  = "winauth"
        vg2txt GAuthUnix = "unixauth"
        vg2txt GInfo     = "info"
        vg2txt GCron     = "cron"
        vg2txt GNet      = "network"
        parsevg "errors"     = Just GErrors
        parsevg "packages"   = Just GPackages
        parsevg "winauth"    = Just GAuthWin
        parsevg "unixauth"   = Just GAuthUnix
        parsevg "info"       = Just GInfo
        parsevg "cron"       = Just GCron
        parsevg "filesystem" = Just GFS
        parsevg "network"    = Just GNet
        parsevg "misc"       = Just GMisc
        parsevg _            = Nothing

$(deriveBoth (defaultOptionsDropLower 3) ''FileVuln)
$(deriveBoth ((defaultOptionsDropLower 4) { constructorTagModifier = drop 4 }) ''RegistryHive)
$(deriveBoth ((defaultOptionsDropLower 2) { constructorTagModifier = drop 2 }) ''RegistryValue)
$(deriveBoth ((defaultOptionsDropLower 4) { constructorTagModifier = drop 4 }) ''UserAccountControlFlag)
$(deriveBoth (defaultOptionsDropLower 4) ''RegistryKey)
$(deriveBoth (defaultOptionsDropLower 4) ''WinLogonInfo)
$(deriveBoth (defaultOptionsDropLower 0) ''Vulnerability)
$(deriveBoth (defaultOptionsDropLower 0) ''ConfigInfo)
$(deriveBoth (defaultOptionsDropLower 7) ''VulnType)
$(deriveBoth (defaultOptionsDropLower 0) ''AuditFileType)
$(deriveBoth (defaultOptionsDropLower 0) ''Severity)
$(deriveBoth (defaultOptionsDropLower 0) ''FileType)
$(deriveBoth (defaultOptionsDropLower 5) ''UnixFileGen)
$(deriveBoth (defaultOptionsDropLower 0) ''RHCond)
$(deriveBoth (defaultOptionsDropLower 6) ''Rhost)
$(deriveBoth (defaultOptionsDropLower 3) ''UnixUser)
$(deriveBoth (defaultOptionsDropLower 9) ''WinGroup)
$(deriveBoth (defaultOptionsDropLower 6) ''RPMVersion)
$(deriveBoth (defaultOptionsDropLower 4) ''WinUser)
$(deriveBoth (defaultOptionsDropLower 4) ''PasswdEntry)
$(deriveBoth (defaultOptionsDropLower 7) ''ShadowEntry)
$(deriveBoth (defaultOptionsDropLower 6) ''GroupEntry)
$(deriveBoth (defaultOptionsDropLower 0) ''ShadowHash)
$(deriveBoth (defaultOptionsDropLower 0) ''UnixType)
$(deriveBoth (defaultOptionsDropLower 0) ''UnixVersion)
$(deriveBoth (defaultOptionsDropLower 0) ''PType)
$(deriveBoth (defaultOptionsDropLower 8) ''SoftwarePackage)
$(deriveBoth (defaultOptionsDropLower 9) ''SolarisPatch)
$(deriveBoth (defaultOptionsDropLower 4) ''ConnectionState)
$(deriveBoth (defaultOptionsDropLower 5) ''CronEntry)
$(deriveBoth (defaultOptionsDropLower 0) ''CronSchedule)
$(deriveBoth (defaultOptionsDropLower 0) ''CError)
$(deriveBoth (defaultOptionsDropLower 1) ''IPProto)
$(deriveBoth (defaultOptionsDropLower 1) ''Connection)
$(deriveBoth (defaultOptionsDropLower 3) ''NetIf)
$(deriveBoth (defaultOptionsDropLower 0) ''Negatable)
$(deriveBoth (defaultOptionsDropLower 0) ''SudoCommand)
$(deriveBoth (defaultOptionsDropLower 0) ''SudoUserId)
$(deriveBoth (defaultOptionsDropLower 0) ''SudoHostId)
$(deriveBoth (defaultOptionsDropLower 0) ''SudoPasswdSituation)
$(deriveBoth (defaultOptionsDropLower 5) ''Sudo)



