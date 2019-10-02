{-# LANGUAGE DeriveGeneric     #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell   #-}
module Analysis.Windows.ACE where

import           Control.Applicative
import           Control.Lens
import           Control.Monad
import           Data.Aeson              hiding (defaultOptions)
import qualified Data.Map.Strict         as M
import qualified Data.Set                as S
import           Data.Text               (Text, pack)
import           Data.Textual
import           Data.Textual.Integral
import           Data.Tuple              (swap)
import           Data.Word
import           Elm.Derive
import           GHC.Generics            (Generic)
import           Prelude                 hiding (print)
import qualified Text.Parser.Char        as P
import qualified Text.Parser.Combinators as P
import           Text.Printer            (text)
import           Text.Printer.Integral   (nnLowHex)

import           Analysis.Windows.GUID
import           Analysis.Windows.SID

data SecurityDescriptor = SecurityDescriptor { _sdType  :: SDType
                                             , _sdOwner :: Maybe RSID
                                             , _sdGroup :: Maybe RSID
                                             , _sdDACL  :: !(ACL DACL)
                                             , _sdSACL  :: !(ACL SACL)
                                             } deriving (Show, Eq)

data SDType = SDRegistry
            | SDAppidAccess
            | SDAppidLaunch
            | SDService
            | SDFile
            | SDPipe
            | SDProcess
            | SDTaskV2
            | SDSCM
            deriving (Show, Eq, Ord, Enum, Bounded)

data RSID = DomainRelative !Word64
          | RSID !SID
          deriving (Eq, Ord, Generic)

data ACL a = ACL { _aclFlags :: S.Set ACLFlag
                 , _aclACEs  :: [ACE]
                 } deriving (Show, Eq)

nullACL :: ACL a
nullACL = ACL (S.singleton SSDL_NULL_ACL) []

data DACL

data SACL

instance Printable (ACL a) where
    print (ACL flags aces) = foldMap print flags <> foldMap (parens . print) aces
        where
            parens x = "(" <> x <> ")"

instance Textual (ACL a) where
    textual = ACL <$> fmap S.fromList (many textual)
                  <*> many (P.char '(' *> textual <* P.char ')')

instance ToJSON (ACL a) where
    toJSON = String . toText

instance FromJSON (ACL a) where
    parseJSON = withText "ACL" $ \t -> case fromText t of
                                           Just x -> pure x
                                           Nothing -> fail ("Bad ACL: " ++ show t)

data ACLFlag = SDDL_PROTECTED
             | SDDL_AUTO_INHERIT_REQ
             | SDDL_AUTO_INHERITED
             | SSDL_NULL_ACL
             deriving (Eq, Ord, Generic, Enum, Bounded)

data ACEType = SDDL_ACCESS_ALLOWED
             | SDDL_ACCESS_DENIED
             | SDDL_OBJECT_ACCESS_ALLOWED
             | SDDL_OBJECT_ACCESS_DENIED
             | SDDL_AUDIT
             | SDDL_ALARM
             | SDDL_OBJECT_AUDIT
             | SDDL_OBJECT_ALARM
             | SDDL_MANDATORY_LABEL
             | SDDL_CALLBACK_ACCESS_ALLOWED
             | SDDL_CALLBACK_ACCESS_DENIED
             | SDDL_RESOURCE_ATTRIBUTE
             | SDDL_SCOPED_POLICY_ID
             | SDDL_CALLBACK_AUDIT
             | SDDL_CALLBACK_OBJECT_ACCESS_ALLOWED
             deriving (Eq, Ord, Generic, Enum, Bounded)

instance Printable ACEType where
    print a = case a of
                  SDDL_ACCESS_ALLOWED                 -> "A"
                  SDDL_ACCESS_DENIED                  -> "D"
                  SDDL_OBJECT_ACCESS_ALLOWED          -> "OA"
                  SDDL_OBJECT_ACCESS_DENIED           -> "OD"
                  SDDL_AUDIT                          -> "AU"
                  SDDL_ALARM                          -> "AL"
                  SDDL_OBJECT_AUDIT                   -> "OU"
                  SDDL_OBJECT_ALARM                   -> "OL"
                  SDDL_MANDATORY_LABEL                -> "ML"
                  SDDL_CALLBACK_ACCESS_ALLOWED        -> "XA"
                  SDDL_CALLBACK_ACCESS_DENIED         -> "XD"
                  SDDL_RESOURCE_ATTRIBUTE             -> "RA"
                  SDDL_SCOPED_POLICY_ID               -> "SP"
                  SDDL_CALLBACK_AUDIT                 -> "XU"
                  SDDL_CALLBACK_OBJECT_ACCESS_ALLOWED -> "ZA"

instance Textual ACEType where
    textual = (SDDL_OBJECT_ACCESS_ALLOWED          <$ P.try (P.string "OA"))
          <|> (SDDL_OBJECT_ACCESS_DENIED           <$ P.try (P.string "OD"))
          <|> (SDDL_AUDIT                          <$ P.try (P.string "AU"))
          <|> (SDDL_ALARM                          <$ P.try (P.string "AL"))
          <|> (SDDL_OBJECT_AUDIT                   <$ P.try (P.string "OU"))
          <|> (SDDL_OBJECT_ALARM                   <$ P.try (P.string "OL"))
          <|> (SDDL_MANDATORY_LABEL                <$ P.try (P.string "ML"))
          <|> (SDDL_CALLBACK_ACCESS_ALLOWED        <$ P.try (P.string "XA"))
          <|> (SDDL_CALLBACK_ACCESS_DENIED         <$ P.try (P.string "XD"))
          <|> (SDDL_RESOURCE_ATTRIBUTE             <$ P.try (P.string "RA"))
          <|> (SDDL_SCOPED_POLICY_ID               <$ P.try (P.string "SP"))
          <|> (SDDL_CALLBACK_AUDIT                 <$ P.try (P.string "XU"))
          <|> (SDDL_CALLBACK_OBJECT_ACCESS_ALLOWED <$ P.try (P.string "ZA"))
          <|> (SDDL_ACCESS_ALLOWED                 <$ P.try (P.string "A"))
          <|> (SDDL_ACCESS_DENIED                  <$ P.try (P.string "D"))

instance Show ACEType where
    show = toString

data ACEFlag = SDDL_CONTAINER_INHERIT
             | SDDL_OBJECT_INHERIT
             | SDDL_NO_PROPAGATE
             | SDDL_INHERIT_ONLY
             | SDDL_INHERITED
             | SDDL_AUDIT_SUCCESS
             | SDDL_AUDIT_FAILURE
             deriving (Eq, Ord, Generic, Enum, Bounded)

instance Printable ACEFlag where
    print a = case a of
                  SDDL_CONTAINER_INHERIT -> "CI"
                  SDDL_OBJECT_INHERIT    -> "OI"
                  SDDL_NO_PROPAGATE      -> "NP"
                  SDDL_INHERIT_ONLY      -> "IO"
                  SDDL_INHERITED         -> "ID"
                  SDDL_AUDIT_SUCCESS     -> "SA"
                  SDDL_AUDIT_FAILURE     -> "FA"

instance Show ACEFlag where
    show = toString

instance Textual ACEFlag where
    textual = (SDDL_CONTAINER_INHERIT <$ P.try (P.string "CI"))
          <|> (SDDL_OBJECT_INHERIT    <$ P.try (P.string "OI"))
          <|> (SDDL_NO_PROPAGATE      <$ P.try (P.string "NP"))
          <|> (SDDL_INHERIT_ONLY      <$ P.try (P.string "IO"))
          <|> (SDDL_INHERITED         <$ P.try (P.string "ID"))
          <|> (SDDL_AUDIT_SUCCESS     <$ P.try (P.string "SA"))
          <|> (SDDL_AUDIT_FAILURE     <$ P.try (P.string "FA"))

data ACEAccessRight = SDDL_GENERIC_ALL
                    | SDDL_GENERIC_READ
                    | SDDL_GENERIC_WRITE
                    | SDDL_GENERIC_EXECUTE
                    | SDDL_READ_CONTROL
                    | SDDL_STANDARD_DELETE
                    | SDDL_WRITE_DAC
                    | SDDL_WRITE_OWNER
                    | SDDL_READ_PROPERTY
                    | SDDL_WRITE_PROPERTY
                    | SDDL_CREATE_CHILD
                    | SDDL_DELETE_CHILD
                    | SDDL_LIST_CHILDREN
                    | SDDL_SELF_WRITE
                    | SDDL_LIST_OBJECT
                    | SDDL_DELETE_TREE
                    | SDDL_CONTROL_ACCESS
                    | SDDL_FILE_ALL
                    | SDDL_FILE_READ
                    | SDDL_FILE_WRITE
                    | SDDL_FILE_EXECUTE
                    | SDDL_KEY_ALL
                    | SDDL_KEY_READ
                    | SDDL_KEY_WRITE
                    | SDDL_KEY_EXECUTE
                    | SDDL_NO_READ_UP
                    | SDDL_NO_WRITE_UP
                    | SDDL_NO_EXECUTE_UP
                    deriving (Eq, Ord, Generic, Enum, Bounded)

instance Printable ACEAccessRight where
    print a = case a of
                  SDDL_GENERIC_ALL     -> "GA"
                  SDDL_GENERIC_READ    -> "GR"
                  SDDL_GENERIC_WRITE   -> "GW"
                  SDDL_GENERIC_EXECUTE -> "GX"
                  SDDL_READ_CONTROL    -> "RC"
                  SDDL_STANDARD_DELETE -> "SD"
                  SDDL_WRITE_DAC       -> "WD"
                  SDDL_WRITE_OWNER     -> "WO"
                  SDDL_READ_PROPERTY   -> "RP"
                  SDDL_WRITE_PROPERTY  -> "WP"
                  SDDL_CREATE_CHILD    -> "CC"
                  SDDL_DELETE_CHILD    -> "DC"
                  SDDL_LIST_CHILDREN   -> "LC"
                  SDDL_SELF_WRITE      -> "SW"
                  SDDL_LIST_OBJECT     -> "LO"
                  SDDL_DELETE_TREE     -> "DT"
                  SDDL_CONTROL_ACCESS  -> "CR"
                  SDDL_FILE_ALL        -> "FA"
                  SDDL_FILE_READ       -> "FR"
                  SDDL_FILE_WRITE      -> "FW"
                  SDDL_FILE_EXECUTE    -> "FX"
                  SDDL_KEY_ALL         -> "KA"
                  SDDL_KEY_READ        -> "KR"
                  SDDL_KEY_WRITE       -> "KW"
                  SDDL_KEY_EXECUTE     -> "KX"
                  SDDL_NO_READ_UP      -> "NR"
                  SDDL_NO_WRITE_UP     -> "NW"
                  SDDL_NO_EXECUTE_UP   -> "NX"

instance Textual ACEAccessRight where
    textual = (SDDL_GENERIC_ALL     <$ P.try (P.string "GA"))
          <|> (SDDL_GENERIC_READ    <$ P.try (P.string "GR"))
          <|> (SDDL_GENERIC_WRITE   <$ P.try (P.string "GW"))
          <|> (SDDL_GENERIC_EXECUTE <$ P.try (P.string "GX"))
          <|> (SDDL_READ_CONTROL    <$ P.try (P.string "RC"))
          <|> (SDDL_STANDARD_DELETE <$ P.try (P.string "SD"))
          <|> (SDDL_WRITE_DAC       <$ P.try (P.string "WD"))
          <|> (SDDL_WRITE_OWNER     <$ P.try (P.string "WO"))
          <|> (SDDL_READ_PROPERTY   <$ P.try (P.string "RP"))
          <|> (SDDL_WRITE_PROPERTY  <$ P.try (P.string "WP"))
          <|> (SDDL_CREATE_CHILD    <$ P.try (P.string "CC"))
          <|> (SDDL_DELETE_CHILD    <$ P.try (P.string "DC"))
          <|> (SDDL_LIST_CHILDREN   <$ P.try (P.string "LC"))
          <|> (SDDL_SELF_WRITE      <$ P.try (P.string "SW"))
          <|> (SDDL_LIST_OBJECT     <$ P.try (P.string "LO"))
          <|> (SDDL_DELETE_TREE     <$ P.try (P.string "DT"))
          <|> (SDDL_CONTROL_ACCESS  <$ P.try (P.string "CR"))
          <|> (SDDL_FILE_ALL        <$ P.try (P.string "FA"))
          <|> (SDDL_FILE_READ       <$ P.try (P.string "FR"))
          <|> (SDDL_FILE_WRITE      <$ P.try (P.string "FW"))
          <|> (SDDL_FILE_EXECUTE    <$ P.try (P.string "FX"))
          <|> (SDDL_KEY_ALL         <$ P.try (P.string "KA"))
          <|> (SDDL_KEY_READ        <$ P.try (P.string "KR"))
          <|> (SDDL_KEY_WRITE       <$ P.try (P.string "KW"))
          <|> (SDDL_KEY_EXECUTE     <$ P.try (P.string "KX"))
          <|> (SDDL_NO_READ_UP      <$ P.try (P.string "NR"))
          <|> (SDDL_NO_WRITE_UP     <$ P.try (P.string "NW"))
          <|> (SDDL_NO_EXECUTE_UP   <$ P.try (P.string "NX"))

instance Show ACEAccessRight where
    show = toString

data ACE = ACE { _aceType              :: ACEType
               , _aceFlags             :: S.Set ACEFlag
               , _aceRights            :: Either Word64 (S.Set ACEAccessRight)
               , _aceObjectGUID        :: Maybe GUID
               , _aceInheritObjectGUID :: Maybe GUID
               , _aceAccountSid        :: RSID
               , _aceResourceAttribute :: Maybe Text
               } deriving (Eq, Show)

instance Printable ACE where
    print (ACE t f r oid ioid sid ra) = print t
                              <> ";" <> foldMap print f
                              <> ";" <> either (\w -> "0x" <> nnLowHex w) (foldMap print) r
                              <> ";" <> foldMap print oid
                              <> ";" <> foldMap print ioid
                              <> ";" <> print sid
                              <> ";" <> foldMap text ra

instance Textual ACE where
    textual = do
        t <- textual
        void (P.char ';')
        f <- S.fromList <$> many textual
        void (P.char ';')
        r <- (P.text "0x" *> fmap Left (nonNegative Hexadecimal))
         <|> (Right . S.fromList <$> many textual)
        void (P.char ';')
        oid <- optional textual
        void (P.char ';')
        ioid <- optional textual
        void (P.char ';')
        sid <- textual
        ra <- optional $ do
            void (P.char ';')
            pack <$> parens
        return (ACE t f r oid ioid sid ra)
      where
        parenssegs = some (P.satisfy (\x -> x /= ')' && x /= '(')) <|> parens
        parens = do
            void (P.char '(')
            segs <- many parenssegs
            void (P.char ')')
            return (mconcat segs)

instance Printable RSID where
    print rs = maybe df text (M.lookup rs textRSID)
        where
            df = case rs of
                     RSID s           -> print s
                     DomainRelative x -> "S-1-DOMAIN-" <> print x

instance Show RSID where
    show = toString

instance Textual RSID where
    textual = P.try known <|> (RSID <$> textual)
        where
            known = do
                pair <- replicateM 2 P.upper
                case M.lookup (pack pair) twoLetterRSID of
                    Just rsid -> return rsid
                    Nothing   -> P.unexpected pair

instance ToJSON RSID where
    toJSON = String . toText

instance FromJSON RSID where
    parseJSON = withText "RSID" $ \t -> case fromText t of
                                            Just x -> pure x
                                            Nothing -> fail ("Bad RSID: " ++ show t)


instance Show ACLFlag where
    show = toString

instance Printable ACLFlag where
    print f = case f of
                  SDDL_PROTECTED        -> "P"
                  SDDL_AUTO_INHERIT_REQ -> "AR"
                  SDDL_AUTO_INHERITED   -> "AI"
                  SSDL_NULL_ACL         -> "NO_ACCESS_CONTROL"

instance Textual ACLFlag where
    textual = P.try $ do
        c <- P.upper
        case c of
            'P' -> pure SDDL_PROTECTED
            'A' -> (SDDL_AUTO_INHERIT_REQ <$ P.char 'R' ) <|> (SDDL_AUTO_INHERITED <$ P.char 'I')
            'N' -> (SSDL_NULL_ACL <$ P.text "O_ACCESS_CONTROL")
            _ -> P.unexpected ("ACL flag starting with " ++ show c)

ntAuthority :: Word64 -> RSID
ntAuthority x = RSID (SID 1 5 [x])

integrityLevel :: Word64 -> RSID
integrityLevel x = RSID (SID 1 16 [x])

textRSID :: M.Map RSID Text
textRSID = M.fromList (map swap (M.toList twoLetterRSID))

twoLetterRSID :: M.Map Text RSID
twoLetterRSID = M.fromList
    [ ("AA", RSID (SID 1 5 [32,579]))
    , ("AC", RSID (SID 1 15 [2,1]))
    , ("AN", RSID (SID 1 5 [7]))
    , ("AO", RSID (SID 1 5 [32,548]))
    , ("AS", RSID (SID 1 18 [1]))
    , ("AU", RSID (SID 1 5 [11]))
    , ("BA", RSID (SID 1 5 [32,544]))
    , ("BG", RSID (SID 1 5 [32,546]))
    , ("BO", RSID (SID 1 5 [32,551]))
    , ("BU", RSID (SID 1 5 [32,545]))
    , ("CD", RSID (SID 1 5 [32,574]))
    , ("CG", RSID (SID 1 3 [1]))
    , ("CO", RSID (SID 1 3 [0]))
    , ("CY", RSID (SID 1 5 [32,569]))
    , ("ED", RSID (SID 1 5 [9]))
    , ("ER", RSID (SID 1 5 [32,573]))
    , ("ES", RSID (SID 1 5 [32,576]))
    , ("HA", RSID (SID 1 5 [32,578]))
    , ("HI", RSID (SID 1 16 [12288]))
    , ("IS", RSID (SID 1 5 [32,568]))
    , ("IU", RSID (SID 1 5 [4]))
    , ("LA", DomainRelative 500)
    , ("LG", DomainRelative 501)
    , ("LS", RSID (SID 1 5 [19]))
    , ("LU", RSID (SID 1 5 [32,559]))
    , ("LW", RSID (SID 1 16 [4096]))
    , ("ME", RSID (SID 1 16 [8192]))
    , ("MP", RSID (SID 1 16 [8448]))
    , ("MS", RSID (SID 1 5 [32,577]))
    , ("MU", RSID (SID 1 5 [32,558]))
    , ("NO", RSID (SID 1 5 [32,556]))
    , ("NS", RSID (SID 1 5 [20]))
    , ("NU", RSID (SID 1 5 [2]))
    , ("OW", RSID (SID 1 3 [4]))
    , ("PO", RSID (SID 1 5 [32,550]))
    , ("PS", RSID (SID 1 5 [10]))
    , ("PU", RSID (SID 1 5 [32,547]))
    , ("RA", RSID (SID 1 5 [32,575]))
    , ("RC", RSID (SID 1 5 [12]))
    , ("RD", RSID (SID 1 5 [32,555]))
    , ("RE", RSID (SID 1 5 [32,552]))
    , ("RM", RSID (SID 1 5 [32,580]))
    , ("RU", RSID (SID 1 5 [32,554]))
    , ("SI", RSID (SID 1 16 [16384]))
    , ("SO", RSID (SID 1 5 [32,549]))
    , ("SS", RSID (SID 1 18 [2]))
    , ("SU", RSID (SID 1 5 [6]))
    , ("SY", RSID (SID 1 5 [18]))
    , ("UD", RSID (SID 1 5 [84,0,0,0,0,0]))
    , ("WD", RSID (SID 1 1 [0]))
    , ("WR", RSID (SID 1 5 [33]))
    ]

makeLenses ''SecurityDescriptor
makePrisms ''ACLFlag
makePrisms ''RSID
$(deriveBoth (defaultOptionsDropLower 3) ''SecurityDescriptor)
$(deriveBoth (defaultOptions{ constructorTagModifier = drop 2 }) ''SDType)

resolveRSID :: SID -- ^ domain SID
            -> RSID
            -> SID
resolveRSID s rsid =
    case rsid of
        DomainRelative r -> s & sidRIDs %~ (++ [r])
        RSID sid         -> sid

knownSIDMap :: SID -> M.Map SID Text
knownSIDMap s = M.fromList $ do
    (t, rs) <- M.toList twoLetterRSID
    return (resolveRSID s rs, t)

