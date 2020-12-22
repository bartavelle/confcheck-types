{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE DeriveGeneric     #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE StrictData        #-}
{-# LANGUAGE TemplateHaskell   #-}
module Analysis.Types.Helpers where

import           Data.Aeson
import qualified Data.Aeson.Types     as A
import           Data.Attoparsec.Text (parseOnly)
import qualified Data.ByteString      as BS
import           Data.Serialize       (Serialize (..))
import           Data.Text            (Text)
import qualified Data.Text.Encoding   as T
import           Data.Textual
import           Data.Time            (Day, fromGregorian, toGregorian)
import           Elm.Derive
import           GHC.Generics         (Generic)
import           Network.IP.Addr

data AuditFileType = AuditTar
                   | AuditTarGz
                   | MBSAReport
                   | WinVBSReport
                   | MissingKBs
                   | WinAuditTool
                   deriving (Eq, Ord, Enum, Generic, Show)

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

fromJsonTextual :: Textual a => A.Value -> A.Parser a
fromJsonTextual = withText "string" $ \x -> case parseOnly textual x of
                                                Right r -> return r
                                                Left rr -> fail rr

-- some error type
data CError = MiscError Text
            | ParsingError Text String (Maybe Text) -- source name, error, original line
            deriving (Show, Eq, Generic)

$(deriveBoth (defaultOptionsDropLower 0) ''AuditFileType)
$(deriveBoth (defaultOptionsDropLower 0) ''CError)
