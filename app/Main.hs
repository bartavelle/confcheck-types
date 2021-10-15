{-# LANGUAGE OverloadedStrings #-}

module Main where

import Analysis.Fiche
import Analysis.Types
import Data.Condition
import Data.Proxy
import qualified Data.Text as T
import Elm.Module

fixes :: String -> String
fixes = T.unpack . fixJMap . T.pack
  where
    fixJMap =
      T.replace "(JMap Int)" "Dict Int"
        . T.replace "(JMap RPMVersion)" "Dict RPMVersion"

main :: IO ()
main =
  putStrLn $
    unlines
      [ "module Confcheck.Types where",
        fixes $
          makeModuleContent
            [ DefineElm (Proxy :: Proxy FileVuln),
              DefineElm (Proxy :: Proxy Vulnerability),
              DefineElm (Proxy :: Proxy ConfigInfo),
              DefineElm (Proxy :: Proxy VulnType),
              DefineElm (Proxy :: Proxy AuditFileType),
              DefineElm (Proxy :: Proxy Severity),
              DefineElm (Proxy :: Proxy FileType),
              DefineElm (Proxy :: Proxy (UnixFileGen a b)),
              DefineElm (Proxy :: Proxy RHCond),
              DefineElm (Proxy :: Proxy Rhost),
              DefineElm (Proxy :: Proxy UnixUser),
              DefineElm (Proxy :: Proxy WinGroup),
              DefineElm (Proxy :: Proxy RPMVersion),
              DefineElm (Proxy :: Proxy WinUser),
              DefineElm (Proxy :: Proxy WindowsService),
              DefineElm (Proxy :: Proxy PasswdEntry),
              DefineElm (Proxy :: Proxy ShadowEntry),
              DefineElm (Proxy :: Proxy GroupEntry),
              DefineElm (Proxy :: Proxy ShadowHash),
              DefineElm (Proxy :: Proxy UnixType),
              DefineElm (Proxy :: Proxy UnixVersion),
              DefineElm (Proxy :: Proxy PType),
              DefineElm (Proxy :: Proxy SoftwarePackage),
              DefineElm (Proxy :: Proxy SolarisPatch),
              DefineElm (Proxy :: Proxy ConnectionState),
              DefineElm (Proxy :: Proxy CronEntry),
              DefineElm (Proxy :: Proxy CronSchedule),
              DefineElm (Proxy :: Proxy CError),
              DefineElm (Proxy :: Proxy IPProto),
              DefineElm (Proxy :: Proxy Connection),
              DefineElm (Proxy :: Proxy NetIf),
              DefineElm (Proxy :: Proxy (Negatable a)),
              DefineElm (Proxy :: Proxy SudoCommand),
              DefineElm (Proxy :: Proxy SudoUserId),
              DefineElm (Proxy :: Proxy SudoHostId),
              DefineElm (Proxy :: Proxy SudoPasswdSituation),
              DefineElm (Proxy :: Proxy Sudo),
              DefineElm (Proxy :: Proxy FicheInfo),
              DefineElm (Proxy :: Proxy FicheApplication),
              DefineElm (Proxy :: Proxy AppServer),
              DefineElm (Proxy :: Proxy AppClient),
              DefineElm (Proxy :: Proxy PackageUniqInfo),
              DefineElm (Proxy :: Proxy (Condition a)),
              DefineElm (Proxy :: Proxy RegistryKey),
              DefineElm (Proxy :: Proxy RegistryHive),
              DefineElm (Proxy :: Proxy RegistryValue),
              DefineElm (Proxy :: Proxy WinLogonInfo),
              DefineElm (Proxy :: Proxy SecurityDescriptor),
              DefineElm (Proxy :: Proxy (Multiple a)),
              DefineElm (Proxy :: Proxy OutdatedPackage),
              DefineElm (Proxy :: Proxy MissingPatch),
              DefineElm (Proxy :: Proxy WrongSysctl)
            ]
      ]
