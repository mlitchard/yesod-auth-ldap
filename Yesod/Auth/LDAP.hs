{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE CPP #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE OverloadedStrings #-}

-- Plugin LDAP authentication for Yesod, based heavily on Yesod.Auth.Kerberos.
-- Verify that your LDAP installation can bind and return LDAP objects before
-- trying to use this module.


-- sample manual LDAP code here

-- 

module Yesod.Auth.LDAP
   ( genericAuthLDAP ) where

#include "qq.h"

import Yesod.Auth
import Yesod.Auth.Message
import Web.Authenticate.LDAP
import LDAP
import Data.Text (Text,pack,unpack)
import Text.Hamlet
import Yesod.Handler
import Yesod.Widget
import Control.Monad.IO.Class (liftIO)
import Yesod.Form
import Control.Applicative ((<$>), (<*>))

data LDAPConfig = LDAPConfig {
   -- | When a user gives username x, f(x) will be passed to Kerberos
   usernameModifier :: Text -> Text
   -- | When a user gives username x, f(x) will be passed to Yesod
 , identifierModifier :: Text -> [LDAPEntry] -> Text
 , ldapHost :: String
 , ldapPort' :: LDAPInt
 , initDN :: String -- DN for initial binding, must have authority to search
 , initPass :: String -- Password for initDN
 , baseDN :: Maybe String -- Base DN for user search, if any
 , ldapScope :: LDAPScope
 }  


genericAuthLDAP :: YesodAuth m => LDAPConfig -> AuthPlugin m
genericAuthLDAP config = AuthPlugin "LDAP" dispatch $ \tm -> addHamlet
    [QQ(hamlet)|
    <div id="header">
         <h1>Login

    <div id="login">
        <form method="post" action="@{tm login}">
            <table>
                <tr>
                    <th>Username:
                    <td>
                        <input id="x" name="username" autofocus="" required>
                <tr>
                    <th>Password:
                    <td>
                        <input type="password" name="password" required>
                <tr>
                    <td>&nbsp;
                    <td>
                        <input type="submit" value="Login">

            <script>
                if (!("autofocus" in document.createElement("input"))) {
                    document.getElementById("x").focus();
                }
|]
  where
    dispatch "POST" ["login"] = postLoginR config >>= sendResponse
    dispatch _ _              = notFound

login :: AuthRoute
login = PluginR "LDAP" ["login"]


postLoginR :: (YesodAuth y) => LDAPConfig -> GHandler Auth y ()
postLoginR config = do
    (mu,mp) <- runInputPost $ (,)
        <$> iopt textField "username"
        <*> iopt textField "password"

    let errorMessage (message :: Text) = do
        setMessage [QQ(shamlet)|Error: #{message}|]
        toMaster <- getRouteToMaster
        redirect $ toMaster LoginR

    case (mu,mp) of
        (Nothing, _      ) -> do
            mr <- getMessageRender
            errorMessage $ mr PleaseProvideUsername
        (_      , Nothing) -> do
            mr <- getMessageRender
            errorMessage $ mr PleaseProvidePassword
        (Just u , Just p ) -> do
          result <- liftIO $ loginLDAP (usernameModifier config u) 
                                       (unpack p)
                                       (ldapHost config)
                                       (ldapPort' config)
                                       (initDN config)
                                       (initPass config)
                                       (baseDN config)
                                       (ldapScope config)
                                       
                                       
          case result of
            Ok ldapEntries -> do
                 let creds = Creds
                       { credsIdent  = identifierModifier config u ldapEntries 
                       , credsPlugin = "LDAP"
                       , credsExtra  = []
                       }
                 setCreds True creds
            ldapError -> errorMessage (pack $ show ldapError)

