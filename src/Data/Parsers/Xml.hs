module Data.Parsers.Xml
    ( Parser
    , ParserT
    , xmldeclaration
    , startelement
    , endelement
    , element
    , element_
    , lx
    , extractParameter
    , getTextFrom
    , getTextFrom0
    , parseTextFrom
    , anyElement
    , elementPred
    , elementPred'
    , elementRPred
    , ignoreNested
    , ignoreElement
    , characterdata
    , xml
    , parseStream
    , parseStreamT
    , initStream
    , parseFile
    , testParse
    , P.try
    , prefixedName
    )
where

import Prelude
import Text.XML.Expat.SAX as S
import Text.Parsec.String ()
import qualified Text.Parsec.Prim as P
import qualified Text.Parsec.Pos as P
import Control.Monad.Identity
import Control.Applicative
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import Data.Monoid
import qualified Data.HashMap.Strict as HM
import qualified Data.ByteString.Lazy as BSL

import qualified ByteString.Parser.Fast as PF

type Parser = P.ParsecT [(SAXEvent T.Text T.Text, XMLParseLocation)] () Identity

type ParserT s m = P.ParsecT [(SAXEvent T.Text T.Text, XMLParseLocation)] s m

tok :: Monad m => (SAXEvent T.Text T.Text -> Maybe a) -> ParserT s m a
tok f = do
    n <- P.sourceName <$> P.getPosition
    let topos (XMLParseLocation ln col _ _) = P.newPos n (fromIntegral ln) (fromIntegral col)
    P.tokenPrim show (\_ (_,p) _ -> topos p) (f . fst)

anyTok :: Monad m => ParserT s m (SAXEvent T.Text T.Text)
anyTok = tok Just

xmldeclaration :: Monad m => ParserT s m (T.Text, Maybe T.Text, Maybe Bool)
xmldeclaration = tok $ \x -> case x of
                                 XMLDeclaration a b c -> Just (a,b,c)
                                 _ -> Nothing

startelement :: Monad m => ParserT s m (T.Text, [(T.Text, T.Text)])
startelement = tok $ \x -> case x of
                               StartElement a b -> Just (a,b)
                               _ -> Nothing

endelement :: Monad m => ParserT s m T.Text
endelement = tok $ \x -> case x of
                             EndElement a -> Just a
                             _ -> Nothing

characterdata :: Monad m => ParserT s m T.Text
characterdata = tok $ \x -> case x of
                             CharacterData a -> Just a
                             _ -> Nothing

comment :: Monad m => ParserT s m T.Text
comment = tok $ \x -> case x of
                          Comment a -> Just a
                          _ -> Nothing

anyElement :: Monad m => (T.Text -> HM.HashMap T.Text T.Text -> ParserT s m a) -> ParserT s m a
anyElement = elementPred' (\_ _ -> True)

prefixedName :: T.Text -> (Maybe T.Text, T.Text)
prefixedName fn =
    case T.splitOn ":" fn of
      [] -> (Nothing, fn)
      [_] -> (Nothing, fn)
      (x:xs) -> (Just x, T.intercalate ":" xs)

elementPred :: Monad m => (Maybe T.Text -> T.Text -> Bool) -> (HM.HashMap T.Text T.Text -> ParserT s m a) -> ParserT s m a
elementPred elpred prs = elementPred' elpred (const prs)

elementPred' :: Monad m => (Maybe T.Text -> T.Text -> Bool) -> (T.Text -> HM.HashMap T.Text T.Text -> ParserT s m a) -> ParserT s m a
elementPred' elpred prs = do
    (elementname, stargs) <- P.try $ do
        (fn, a) <- startelement
        let (prefix, n) = prefixedName fn
        unless (elpred prefix n) (fail ("Unexpected element " <> show n))
        return (fn, a)
    r <- prs elementname (HM.fromList stargs)
    stname' <- endelement
    unless (stname' == elementname) (fail ("Unexpected closing tag " <> T.unpack stname'))
    return r

elementRPred :: Monad m => (T.Text -> Bool) -> (HM.HashMap T.Text T.Text -> ParserT s m a) -> ParserT s m a
elementRPred elpred' = elementPred (const elpred')

element :: Monad m => T.Text -> (HM.HashMap T.Text T.Text -> ParserT s m a) -> ParserT s m a
element elname = elementPred (const (== elname))

element_ :: Monad m => T.Text -> ParserT s m a -> ParserT s m a
element_ elname prs = element elname (const prs)

lx :: Monad m => ParserT s m a -> ParserT s m a
lx p = many (characterdata <|> comment) *> p <* many (characterdata <|> comment)

data NestElement = NEl T.Text
                 | NCd
                 deriving Show

ignoreNested :: Monad m => [NestElement] -> ParserT s m ()
ignoreNested stack = do
    t <- P.lookAhead anyTok
    let nxt st = anyTok *> ignoreNested st
    case t of
        StartElement n _ -> nxt (NEl n : stack)
        StartCData -> nxt (NCd : stack)
        EndElement n -> case stack of
                            (NEl n' : xs) -> if n == n'
                                                 then nxt xs
                                                 else fail ("Expected a closing tag " <> T.unpack n <> " but got " <> T.unpack n' <> " instead, when ignoring stuff")
                            (NCd : _) -> fail ("Expected a closing tag " <> T.unpack n <> " but got an end of cdata instead")
                            [] -> return ()
        EndCData -> case stack of
                        (NCd : xs) -> nxt xs
                        (NEl n' : _) -> fail ("Expected an end of CData but got an end of element " <> T.unpack n' <> " instead, when ignoring stuff")
                        [] -> return ()
        _ -> nxt stack

ignoreElement :: Monad m => T.Text -> ParserT s m ()
ignoreElement elname = element_ elname (ignoreNested [])

extractParameter :: Monad m => T.Text -> HM.HashMap T.Text b -> ParserT s m b
extractParameter k mp = case HM.lookup k mp of
                            Just x -> pure x
                            Nothing -> fail ("Can't find parameter " <> T.unpack k)

getTextFrom :: Monad m => T.Text -> ParserT s m T.Text
getTextFrom n = element_ n (mconcat <$> some characterdata)

getTextFrom0 :: Monad m => T.Text -> ParserT s m T.Text
getTextFrom0 n = element_ n (mconcat <$> many characterdata)

parseTextFrom :: Monad m => PF.Parser a -> T.Text -> ParserT s m a
parseTextFrom prs tag = do
    t <- getTextFrom tag
    case PF.parseOnly prs (T.encodeUtf8 t) of
        Left rr -> fail ("Couldn't parse the content of element " <> T.unpack tag <> ": " <> show rr)
        Right x -> return x

xml :: Monad m => ParserT s m a -> ParserT s m a
xml p = xmldeclaration *> p

parseStream :: FilePath -> BSL.ByteString -> Parser a -> Either String a
parseStream src l p = runIdentity (parseStreamT src l p)

initStream :: BSL.ByteString -> [(SAXEvent T.Text T.Text, XMLParseLocation)]
initStream = S.parseLocations (ParseOptions Nothing Nothing)

parseStreamT :: Monad m => FilePath -> BSL.ByteString -> ParserT () m a -> m (Either String a)
parseStreamT src l p = either (Left . show) Right <$> P.runParserT p () src (initStream l)

parseFile :: FilePath -> Parser a -> IO (Either String a)
parseFile fp p = (\c -> parseStream fp c p) <$> BSL.readFile fp

testParse :: FilePath -> Parser a -> IO a
testParse fp p = either error return =<< parseFile fp p
