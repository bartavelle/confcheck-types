{-# LANGUAGE DeriveFoldable    #-}
{-# LANGUAGE DeriveFunctor     #-}
{-# LANGUAGE DeriveGeneric     #-}
{-# LANGUAGE DeriveTraversable #-}
{-# LANGUAGE TemplateHaskell   #-}
module Data.Condition where

import           Control.Lens
import qualified Data.Foldable  as F
import           Data.List      (nub)
import           Data.Maybe     (mapMaybe)
import           Data.Serialize (Serialize (..))
import           Elm.Derive
import           GHC.Generics
import           Prelude

data Condition a = Pure a
                 | Always Bool
                 | Not (Condition a)
                 | And [Condition a]
                 | Or [Condition a]
                 deriving (Show, Eq, Functor, F.Foldable, Traversable, Generic)

instance Serialize a => Serialize (Condition a) where

makePrisms ''Condition

checkCondition :: (a -> Bool) -> Condition a -> Bool
checkCondition _ (Always x) = x
checkCondition f (Pure a)   = f a
checkCondition f (Not c)    = not (checkCondition f c)
checkCondition f (And cnds) = all (checkCondition f) cnds
checkCondition f (Or cnds)  = any (checkCondition f) cnds

matchingConditions :: (a -> Maybe b) -> Condition a -> Maybe [b]
matchingConditions _ (Always True) = Just []
matchingConditions _ (Always False) = Nothing
matchingConditions f (Pure a) = return <$> f a
matchingConditions f (Not c) = case matchingConditions f c of
                                   Nothing -> Just []
                                   _       -> Nothing
matchingConditions f (And cns) = mconcat <$> Prelude.mapM (matchingConditions f) cns
matchingConditions f (Or cns) = case mapMaybe (matchingConditions f) cns of
                                    [] -> Nothing
                                    xs -> Just (concat xs)


simplifyCond1 :: Eq a => Condition a -> Condition a
simplifyCond1 (Not n) = case sn of
                            Always x -> Always (not x)
                            _        ->  Not sn
    where
        sn = simplifyCond1 n
simplifyCond1 (And [x]) = simplifyCond1 x
simplifyCond1 (Or  [x]) = simplifyCond1 x
simplifyCond1 (And xs) | Always False `elem` sxs = Always False
                       | length sxs == 1 = head sxs
                       | null sxs = Always True
                       | otherwise = And (filter (/= Always True) sxs)
    where
        sxs = nub (map simplifyCond1 xs)
simplifyCond1 (Or  xs) | Always True `elem` sxs = Always True
                       | length sxs == 1 = head sxs
                       | null sxs = Always False
                       | otherwise = Or (filter (/= Always False) sxs)
    where
        sxs = nub $ analyzeOrCondList (map simplifyCond1 xs)
simplifyCond1 (Pure x) = Pure x
simplifyCond1 (Always x) = Always x

collapseCondition :: Condition (Condition x) -> Condition x
collapseCondition (Pure x)   = x
collapseCondition (Always x) = Always x
collapseCondition (Not x)    = Not (collapseCondition x)
collapseCondition (And xs)   = And (map collapseCondition xs)
collapseCondition (Or xs)    = Or (map collapseCondition xs)

analyzeOrCondList :: Eq a => [Condition a] -> [Condition a]
analyzeOrCondList lst = nub $ concatMap filterAnd lst
    where
        filterAnd (And xs) = case filter (`notElem` singleset) xs of
                                 []  -> []
                                 [x] -> [x]
                                 xs' -> [And xs']
        filterAnd (Or xs) = xs
        filterAnd x = [x]
        singleset = map Pure $ nub $ toListOf (folded . _Pure) lst

$(deriveBoth defaultOptions { omitNothingFields = True, sumEncoding = ObjectWithSingleField } ''Condition)

