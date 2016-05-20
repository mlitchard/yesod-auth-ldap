{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE CPP #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE FlexibleContexts #-}

-- Plugin LDAP authentication for Yesod, based heavily on Yesod.Auth.Kerberos.
-- Verify that your LDAP installation can bind and return LDAP objects before
-- trying to use this module.


module Yesod.Auth.LDAP
   ( genericAuthLDAP
   , LDAPConfig (..)) where

import Yesod.Core (lift)
import Yesod.Auth
import Yesod.Auth.Message
import Web.Authenticate.LDAP
import LDAP
import Data.Text (Text,pack,unpack)
import Text.Hamlet
import Yesod.Core.Handler
import Yesod.Core.Widget
import Control.Monad.IO.Class (liftIO)
import Yesod.Form
import Control.Applicative ((<$>), (<*>))
import Control.Arrow ((***))
import qualified Yesod.Auth.Message as Msg

data LDAPConfig = LDAPConfig {
   -- | Given user x, f(x) will be search as a LDAP filter, eg: uid=username
   usernameFilter :: Text -> Text
   -- | When a user gives username x, f(x) will be passed to Yesod
 , identifierModifier :: Text -> LDAPEntry -> Text
 , ldapUri :: String
 , initDN :: String -- DN for initial binding, must have authority to search
 , initPass :: String -- Password for initDN
 , baseDN :: Maybe String -- Base DN for user search, if any
 , ldapScope :: LDAPScope
 }


genericAuthLDAP :: YesodAuth m => LDAPConfig -> AuthPlugin m
genericAuthLDAP config = AuthPlugin "LDAP" dispatch $ \tm -> toWidget
    [whamlet|
        <form method="post" action="@{tm login}">
            <table>
                <tr>
                    <th>LDAP
                    <td>
                        <input type="text" name="username" required>
                <tr>
                    <th>_{Msg.Password}
                    <td>
                        <input type="password" name="password" required>
                <tr>
                    <td colspan="2">
                        <button type=submit .btn .btn-success>Login
|]
  where
    dispatch "POST" ["login_ldap"] = postLoginR config >>= sendResponse
    dispatch _ _ = notFound


login :: AuthRoute
login = PluginR "LDAP" ["login_ldap"]


postLoginR :: (YesodAuth y) => LDAPConfig -> HandlerT Auth (HandlerT y IO) ()
postLoginR config = do
    (mu,mp) <- lift $ runInputPost $ (,)
        <$> iopt textField "username"
        <*> iopt textField "password"

    let errorMessage (message :: Text) = do
        lift $ setMessage [shamlet|Error: #{message}|]
        redirect LoginR

    case (mu,mp) of
        (Nothing, _      ) -> do
            mr <- lift getMessageRender
            errorMessage $ mr PleaseProvideUsername
        (_      , Nothing) -> do
            mr <- lift getMessageRender
            errorMessage $ mr PleaseProvidePassword
        (Just u , Just p ) -> do
          result <- liftIO $ loginLDAP (usernameFilter config u)
                                       (unpack p)
                                       (ldapUri config)
                                       (initDN config)
                                       (initPass config)
                                       (baseDN config)
                                       (ldapScope config)


          case result of
            Ok entry -> do
                 let creds = Creds
                       { credsIdent  = identifierModifier config u entry
                       , credsPlugin = "LDAP"
                       , credsExtra  = map (pack *** pack) $
                           ldapAttrsFlatten $ leattrs entry
                       }
                 lift $ setCreds True creds
            ldapError -> errorMessage (pack $ show ldapError)

{-
We need to flatten the right part because credsExtra is of type [(String,
String)], and we don't want to loose information by converting to Text, we
can have multiple values for the left key. One must be careful when using
the `lookup` function.
-}
ldapAttrsFlatten :: [(a, [b])] -> [(a, b)]
ldapAttrsFlatten = concat . map split
    where split (l, x) = map ((,) l) x
