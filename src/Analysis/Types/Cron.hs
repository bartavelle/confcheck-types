{-# LANGUAGE DeriveGeneric              #-}
{-# LANGUAGE TemplateHaskell            #-}
module Analysis.Types.Cron where

import           Data.Text               (Text)
import           Elm.Derive
import           GHC.Generics            (Generic)

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

$(deriveBoth (defaultOptionsDropLower 5) ''CronEntry)
$(deriveBoth (defaultOptionsDropLower 0) ''CronSchedule)
