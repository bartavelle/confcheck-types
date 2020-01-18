{-# LANGUAGE DeriveTraversable          #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE TemplateHaskell            #-}
{-# LANGUAGE TupleSections              #-}
{-# LANGUAGE TypeFamilies               #-}
module Analysis.Fiche where

import           Analysis.Types.Helpers       (CError (..))
import           Analysis.Types.Network
import           Analysis.Types.Package
import           Analysis.Types.Unix
import           Analysis.Types.UnixUsers
import           Analysis.Types.Vulnerability
import           Analysis.Types.Windows

import           Control.Arrow                ((***))
import           Control.Lens
import           Data.Aeson                   hiding (defaultOptions)
import           Data.Aeson.Types             (Parser)
import           Data.Char                    (toLower)
import qualified Data.HashMap.Strict          as HM
import           Data.List                    (nub)
import qualified Data.Map.Strict              as M
import qualified Data.Set                     as S
import           Data.Text                    (Text)
import qualified Data.Text                    as T
import           Data.Textual
import           Data.Time                    (Day (..), fromGregorian)
import           Data.Word                    (Word16)
import           Elm.Derive

data PackageUniqInfo = PackageUniqInfo { _pckSeverity :: Severity
                                       , _pckDay      :: Day
                                       , _pckVersion  :: RPMVersion
                                       , _pckDesc     :: [T.Text]
                                       , _pckPatches  :: [(Day, RPMVersion, Severity, T.Text)]
                                       }
                                       deriving Show

instance Semigroup PackageUniqInfo where
    PackageUniqInfo s1 d1 pv1 p1 t1 <> PackageUniqInfo s2 d2 pv2 p2 t2 = PackageUniqInfo (max s1 s2) (min d1 d2) (max pv1 pv2) (nub (p1 ++ p2)) (nub (t1 ++ t2))

instance Monoid PackageUniqInfo where
    mempty = PackageUniqInfo Unknown (fromGregorian 1970 1 1) "" [] []

newtype JMap a b = JMap { getJMap :: M.Map a b }
                   deriving (Show, Eq, Ord, Functor, Foldable, Traversable)

instance Ord k => TraverseMin k (JMap k) where
    traverseMin f (JMap x) = JMap <$> traverseMin f x

instance Ord k => TraverseMax k (JMap k) where
    traverseMax f (JMap x) = JMap <$> traverseMax f x

instance (Eq k, Eq v, Ord k, Monoid v) => AsEmpty (JMap k v) where
    _Empty = _Wrapped' . _Empty

instance Ord k => FoldableWithIndex k (JMap k)
instance Ord k => FunctorWithIndex k (JMap k)
instance Ord k => TraversableWithIndex k (JMap k) where
    itraverse f (JMap mp) = JMap <$> itraverse f mp

instance Ord k => Ixed (JMap k a) where
    ix k = _Wrapped' . ix k

instance Ord k => At (JMap k a) where
    at k = _Wrapped' . at k

type instance IxValue (JMap k a) = a
type instance Index (JMap k a) = k

instance (Ord k, Semigroup a) => Semigroup (JMap k a) where
    JMap a <> JMap b = JMap (M.unionWith (<>) a b)

instance (Ord k, Monoid a) => Monoid (JMap k a) where
    mempty = JMap mempty

parseTextual :: Textual a => Text -> Parser a
parseTextual = maybe (fail "cannot decode") return . fromText

instance (Textual a, FromJSON b, Ord a) => FromJSON (JMap a b) where
    parseJSON = withObject "JMap" $ \o -> do
        t <- traverse (\(k,v) -> (,) <$> parseTextual k <*> parseJSON v) (HM.toList o)
        return (JMap (M.fromList t))

instance (Textual a, ToJSON b, Ord a) => ToJSON (JMap a b) where
    toJSON (JMap mp) = object $ map (toText *** toJSON) (M.toList mp)

data Deadline = NoDeadLine
              | Done
              | For Day
              deriving (Show, Ord, Eq)

newtype AppUser = AppUser { _auName :: Text }
                  deriving (Show, FromJSON, ToJSON)

data AppServer
  = AppServer
  { _apsListenOn :: [Text]
  , _apsPort     :: Word16
  , _apsFiltered :: Bool
  , _apsClients  :: [Text]
  } deriving (Show)

data AppClient
  = AppClient
  { _apcConnectTo :: [Text]
  , _apcPort      :: Word16
  } deriving (Show)

data FicheApplication
  = FicheApplication
  { _appName     :: Text
  , _appIdentity :: [Text]
  , _appServer   :: [AppServer]
  , _appClient   :: [AppClient]
  } deriving (Show)

data FicheInfo
  = FicheInfo
  { _ficheOS                 :: UnixVersion
  , _ficheProblems           :: [CError]
  , _fichePackages           :: [(Day, Severity, Text, Text, Text)] -- (update date, severity, package description, installed version, patch version)
  , _ficheUsers              :: ([UnixUser], [UnixUser], [WinUser], [WinUser], M.Map Text [AppUser]) -- (privilégiés, autres){lin,win}, applicatifs
  , _ficheFSProblems         :: [(Severity, FileVuln)]
  , _ficheAnnuaire           :: Maybe Text
  , _fichePkgVulns           :: JMap RPMVersion PackageUniqInfo
  , _ficheIfaces             :: [(Text, Text, Maybe MAC, Maybe Text)]
  , _ficheOldestMissingPatch :: Maybe Day
  , _ficheAllVulns           :: [Vulnerability]
  , _ficheApplications       :: [FicheApplication]
  , _ficheHostname           :: Maybe Text
  } deriving (Show)

$(deriveBoth defaultOptions{ fieldLabelModifier = map toLower . drop 6} ''FicheInfo)
$(deriveBoth defaultOptions{ fieldLabelModifier = map toLower . drop 4} ''AppServer)
$(deriveBoth defaultOptions{ fieldLabelModifier = map toLower . drop 4} ''AppClient)
$(deriveBoth defaultOptions{ fieldLabelModifier = map toLower . drop 4} ''FicheApplication)
$(deriveBoth defaultOptions{ fieldLabelModifier = map toLower . drop 4} ''PackageUniqInfo)

makeWrapped ''JMap
makeLenses ''PackageUniqInfo
makeLenses ''FicheApplication
makeLenses ''FicheInfo

knownUsers :: S.Set T.Text
knownUsers = S.fromList [ "tcpdump"
                        , "nslcd"
                        , "sshd"
                        , "pulse"
                        , "postfix"
                        , "saslauth"
                        , "ntp"
                        , "gdm"
                        , "haldaemon"
                        , "nfsnobody"
                        , "rpcuser"
                        , "abrt"
                        , "avahi-autoipd"
                        , "nscd"
                        , "rpc"
                        , "vcsa"
                        , "dbus"
                        , "nobody"
                        , "ftp"
                        , "gopher"
                        , "games"
                        , "operator"
                        , "uucp"
                        , "mail"
                        , "halt"
                        , "shutdown"
                        , "sync"
                        , "lp"
                        , "adm"
                        , "daemon"
                        , "bin"
                        ]
