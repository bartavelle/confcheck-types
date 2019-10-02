{-# LANGUAGE DeriveGeneric   #-}
{-# LANGUAGE TemplateHaskell #-}
module Analysis.Windows.SID where

import           Control.Applicative
import           Control.Lens
import           Control.Monad
import           Data.Aeson
import           Data.Char
import           Data.Hashable
import           Data.List
import qualified Data.Map.Strict         as M
import           Data.Text               (Text)
import           Data.Textual
import           Data.Word
import           GHC.Generics            (Generic)
import           Prelude                 hiding (print)

import qualified Text.Parser.Char        as P
import qualified Text.Parser.Combinators as P

data SID = SID { _sidRevision  :: !Word32
               , _sidAuthority :: !Word64
               , _sidRIDs      :: [Word64]
               } deriving (Eq, Ord, Generic)

instance Hashable SID

instance Show SID where
    show = toString

instance Printable SID where
    print (SID r a rids) = mconcat (intersperse "-" (["S", print r, print a] ++ map print rids))

rnumber :: (Num n, P.CharParsing m) => m n
rnumber = foldl' (\c n -> c * 10 + fromIntegral (digitToInt n)) 0 <$> many P.digit

instance Textual SID where
    textual = do
        void $ P.char 'S'
        void $ P.char '-'
        r <- rnumber
        void $ P.char '-'
        a <- rnumber
        void $ P.char '-'
        as <- rnumber `P.sepBy` P.char '-'
        return (SID r a as)

instance ToJSON SID where
    toJSON = String . toText

instance FromJSON SID where
    parseJSON = withText "SID" $ \t -> case fromText t of
                                         Just x -> pure x
                                         Nothing -> fail ("Bad SID: " ++ show t)

_SID :: Prism' Text SID
_SID = prism' toText fromText

wellKnownSID :: M.Map SID (Text, Text, Bool) -- (RID, Desc, isAdmin)
wellKnownSID = M.fromList
    [ (SID 1 5 [32, 0x220], ("DOMAIN_ALIAS_RID_ADMINS", "A local group used for administration of the domain.", True) )
    , (SID 1 5 [32, 0x221], ("DOMAIN_ALIAS_RID_USERS", "A local group that represents all users in the domain.", False) )
    , (SID 1 5 [32, 0x222], ("DOMAIN_ALIAS_RID_GUESTS", "A local group that represents guests of the domain.", False) )
    , (SID 1 5 [32, 0x223], ("DOMAIN_ALIAS_RID_POWER_USERS", "A local group used to represent a user or set of users who expect to treat a system as if it were their personal computer rather than as a workstation for multiple users.", True) )
    , (SID 1 5 [32, 0x224], ("DOMAIN_ALIAS_RID_ACCOUNT_OPS", "A local group that exists only on systems running server operating systems. This local group permits control over nonadministrator accounts.", True) )
    , (SID 1 5 [32, 0x225], ("DOMAIN_ALIAS_RID_SYSTEM_OPS", "A local group that exists only on systems running server operating systems. This local group performs system administrative functions, not including security functions. It establishes network shares, controls printers, unlocks workstations, and performs other operations.", True) )
    , (SID 1 5 [32, 0x226], ("DOMAIN_ALIAS_RID_PRINT_OPS", "A local group that exists only on systems running server operating systems. This local group controls printers and print queues.", True) )
    , (SID 1 5 [32, 0x227], ("DOMAIN_ALIAS_RID_BACKUP_OPS", "A local group used for controlling assignment of file backup-and-restore privileges.", True) )
    , (SID 1 5 [32, 0x228], ("DOMAIN_ALIAS_RID_REPLICATOR", "A local group responsible for copying security databases from the primary domain controller to the backup domain controllers. These accounts are used only by the system.", True) )
    , (SID 1 5 [32, 0x229], ("DOMAIN_ALIAS_RID_RAS_SERVERS", "A local group that represents RAS and IAS servers. This group permits access to various attributes of user objects.", True) )
    , (SID 1 5 [32, 0x22a], ("DOMAIN_ALIAS_RID_PREW2KCOMPACCESS", "A local group that exists only on systems running Windows 2000 Server. For more information, see Allowing Anonymous Access.", False) )
    , (SID 1 5 [32, 0x22b], ("DOMAIN_ALIAS_RID_REMOTE_DESKTOP_USERS", "A local group that represents all remote desktop users.", False) )
    , (SID 1 5 [32, 0x22c], ("DOMAIN_ALIAS_RID_NETWORK_CONFIGURATION_OPS", "A local group that represents the network configuration.", True) )
    , (SID 1 5 [32, 0x22d], ("DOMAIN_ALIAS_RID_INCOMING_FOREST_TRUST_BUILDERS", "Members of this group can create incoming, one-way trusts to this forest.", True) )
    , (SID 1 5 [32, 0x22e], ("DOMAIN_ALIAS_RID_MONITORING_USERS", "Members of this group have remote access to monitor this computer.", False) )
    , (SID 1 5 [32, 0x22f], ("DOMAIN_ALIAS_RID_LOGGING_USERS", "Members of this group have remote access to schedule logging of performance counters on this computer.", False) )
    , (SID 1 5 [32, 0x230], ("DOMAIN_ALIAS_RID_AUTHORIZATIONACCESS", "Members of this group have access to the computed tokenGroupsGlobalAndUniversal attribute on User objects.", False) )
    , (SID 1 5 [32, 0x231], ("DOMAIN_ALIAS_RID_TS_LICENSE_SERVERS", "A group for Terminal Server License Servers.", False) )
    , (SID 1 5 [32, 0x232], ("DOMAIN_ALIAS_RID_DCOM_USERS", "A group for COM to provide computerwide access controls that govern access to all call, activation, or launch requests on the computer.", True) )
    , (SID 1 5 [32, 0x238], ("DOMAIN_ALIAS_RID_IUSERS", "A local group that represents Internet users.", False) )
    , (SID 1 5 [32, 0x239], ("DOMAIN_ALIAS_RID_CRYPTO_OPERATORS", "A local group that represents access to cryptography operators.", False) )
    , (SID 1 5 [32, 0x23b], ("DOMAIN_ALIAS_RID_CACHEABLE_PRINCIPALS_GROUP", "Members in this group can have their passwords replicated to all read-only domain controllers in the domain.", False) )
    , (SID 1 5 [32, 0x23c], ("DOMAIN_ALIAS_RID_NON_CACHEABLE_PRINCIPALS_GROUP", "Members in this group cannot have their passwords replicated to any read-only domain controllers in the domain.", False) )
    , (SID 1 5 [32, 0x23d], ("DOMAIN_ALIAS_RID_EVENT_LOG_READERS_GROUP", "A local group that represents event log readers.", False) )
    , (SID 1 5 [32, 0x23e], ("DOMAIN_ALIAS_RID_CERTSVC_DCOM_ACCESS_GROUP", "Members of this group are allowed to connect to Certification Authorities in the enterprise.", False) )
    , (SID 1 5 [32, 578], ("BUILTIN\\Hyper-V Administrators", "Members of this group have complete and unrestricted access to all features of Hyper-V.", True) )
    , (SID 1 5 [32, 580], ("BUILTIN\\Remote Management Users", "Members of this group can access WMI resources over management protocols (such as WS-Management via the Windows Remote Management service). This applies only to WMI namespaces that grant access to the user.", False) )
    , (SID 1 5 [9], ("Enterprise Domain Controllers", "A group that includes all domain controllers in a forest that uses an Active Directory directory service. Membership is controlled by the operating system.", True) )
    , (SID 1 5 [18], ("Local System", "", True) )
    , (SID 1 5 [19], ("Local Service", "", False) )
    , (SID 1 5 [20], ("Network Service", "", False) )
    ]

isAdminSID :: SID -> Bool
isAdminSID s = maybe checkDomain (\(_,_,x) -> x) (M.lookup s wellKnownSID)
    where
        checkDomain = case s of
                          SID 1 5 [_, x] -> x `elem` [500,502,512,516,518,519,520,498,521]
                          _ -> False

makeLenses ''SID
