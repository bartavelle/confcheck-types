{-# LANGUAGE DeriveFoldable    #-}
{-# LANGUAGE DeriveFunctor     #-}
{-# LANGUAGE DeriveGeneric     #-}
{-# LANGUAGE DeriveTraversable #-}
{-# LANGUAGE TemplateHaskell   #-}
module Analysis.Types.Negatable where

import           Control.Comonad
import qualified Data.Foldable   as F
import           Elm.Derive
import           GHC.Generics    (Generic)

import           Data.Condition

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

$(deriveBoth (defaultOptionsDropLower 0) ''Negatable)
