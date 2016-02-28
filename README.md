# spring-security-adfs-saml2 [![Build Status](https://travis-ci.org/choonchernlim/spring-security-adfs-saml2.svg?branch=master)](https://travis-ci.org/choonchernlim/spring-security-adfs-saml2)

Spring Security module for service provider (Sp) to authenticate against identity provider's (IdP) ADFS using SAML protocol.

How this module is configured:-

* `HTTP-Redirect` binding for sending SAML messages to IdP.
* SSO is disabled by forcing IdP login page to appear so that users don't automatically get logged in through Windows Integrated Auth (WIA). 
* Default signature algorithm is SHA256withRSA.
* Default digest algorithm is SHA-256.

Tested against:-

* ADFS 2.0 - Windows Server 2008 R2
* ADFS 2.1 - Windows Server 2012

## Maven Dependency

```xml
<dependency>
  <groupId>com.github.choonchernlim</groupId>
  <artifactId>spring-security-adfs-saml2</artifactId>
  <version>X.X.X</version>
</dependency>
```

## Prerequisites

* Sp must use HTTPS protocol.
* Java’s default keysize is limited to 128-bit key due to US export laws and a few countries’ import laws. So, Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files must be installed to allow larger key size, such as 256-bit key.
* Keystore must contain both Sp's public/private keys and imported IdP's public certificate. 
    * Sp's public/private keys - to generate digital signature before sending SAML messages to IdP.
    * IdP's public certificate - to verify IdP's SAML messages to prevent man-in-the-middle attack.
    * To import IdP's public certificate into keystore:-
        * `keytool -importcert -file idp-adfs-server.cer -keystore keystore.jks -alias "idp-adfs-server"`

## Important SAML Endpoints

There are several SAML processing endpoints, but these are the ones you probably care:-

|Endpoint              |Description                                                                                                                             |
|----------------------|----------------------------------------------------------------------------------------------------------------------------------------|
|`/saml/login`         |Initiates login process between Sp and IdP. Upon successful login, user will be redirected to `SAMLConfigBean.successLoginDefaultUrl`.  |
|`/saml/logout`        |Initiates logout process between Sp and IdP. Upon successful logout, user will be redirected to `SAMLConfigBean.successLogoutUrl`.      |
|`/saml/metadata`      |Returns Sp metadata. IdP may need this link to register Sp on ADFS.                                                                     |

## Relevant Links

Learn about my pains and lessons learned while building this module.

* [Replacing SHA-1 with SHA-256 on Signature and Digest Algorithms](http://myshittycode.com/2016/02/23/spring-security-saml-replacing-sha-1-with-sha-256-on-signature-and-digest-algorithms/)
* [Handling IdP’s Public Certificate When Loading Metadata Over HTTPS](http://myshittycode.com/2016/02/19/spring-security-saml-handling-idps-public-certificate-when-loading-metadata-over-https/)
* [Configuring Binding for Sending SAML Messages to IdP](http://myshittycode.com/2016/02/18/spring-security-saml-configuring-binding-for-sending-saml-messages-to-idp/)

