# Change Log

## 0.3.4 - 2016-06-01

* Dependency, parent and plugins updates.

```                  
com.github.choonchernlim:build-reports ................ 0.2.4 -> 0.3.2
com.google.guava:guava-testlib .......................... 18.0 -> 19.0
junit:junit ............................................. 4.11 -> 4.12
org.codehaus.groovy:groovy-all .............. 2.4.3 -> 2.4.6
org.springframework.security:spring-security-config ...
                                        4.0.3.RELEASE -> 4.1.0.RELEASE
org.springframework.security:spring-security-core ...
                                        4.0.3.RELEASE -> 4.1.0.RELEASE
org.springframework.security:spring-security-web ...
                                        4.0.3.RELEASE -> 4.1.0.RELEASE
org.springframework.security.extensions:spring-security-saml2-core ...
                                        1.0.1.RELEASE -> 1.0.2.RELEASE
maven-compiler-plugin ................................... 3.3 -> 3.5.1
```                       

## 0.3.3 - 2016-04-13                       
* Inject Spring environment to get access to project properties file. ([#1](https://github.com/choonchernlim/spring-security-adfs-saml2/pull/1))

## 0.3.2 - 2016-03-14

* Used `SAMLContextProviderLB` instead of `SAMLContextProviderImpl` to handle servers doing SSL termination.
* Dropped `SAMLConfigBean.spMetadataBaseUrl`.
* Renamed `SAMLConfigBean.adfsHostName` to `SAMLConfigBean.idpHostName`.
* Added `SAMLConfigBean.spServerName`.
* Added `SAMLConfigBean.spHttpsPort`.
* Added `SAMLConfigBean.spContextPath`.

## 0.3.1 - 2016-03-10

* Added `SAMLConfigBean.spMetadataBaseUrl` to manually specify the Sp's metadata base URL to handle situations where servers do SSL termination (HTTPS -> HTTP).
* Configured metadata generator to use user defined Sp's metadata base URL when generating SAML endpoints URLs.

## 0.2.2 - 2016-03-08

* Fixed casing typo from `SAMLConfigBean.keyStoreResource` to `SAMLConfigBean.keystoreResource`.

## 0.2.1 - 2016-03-07

* Added `SAMLConfigBean.keystorePrivateKeyPassword` to add password for private key.
* Kept storepass and keypass separate.
* Excluded `xml-apis` from dependency because it's known to cause problems in WAS.

## 0.2.0 - 2016-03-02

* Options to allow different authentication method. Default is user/password using IdP's form login page.
* `CustomAuthnContext.WINDOWS_INTEGRATED_AUTHN_CTX` to allow Windows Integrated Authentication.

## 0.1.0 - 2016-02-28

* Initial.
