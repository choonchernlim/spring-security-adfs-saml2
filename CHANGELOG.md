# Change Log

## 0.2.1 - 2016-03-07

* Added `SAMLConfigBean.keystorePrivateKeyPassword` to add password for private key.
* Kept storepass and keypass separate.
* Excluded `xml-apis` from dependency because it's known to cause problems in WAS.

## 0.2.0 - 2016-03-02

* Options to allow different authentication method. Default is user/password using IdP's form login page.
* `CustomAuthnContext.WINDOWS_INTEGRATED_AUTHN_CTX` to allow Windows Integrated Authentication.

## 0.1.0 - 2016-02-28

* Initial.
