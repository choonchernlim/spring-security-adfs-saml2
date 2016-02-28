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

## Usage 

```java
@Configuration
@EnableWebSecurity
class AppSecurityConfig extends SAMLWebSecurityConfigurerAdapter {

    // All the parameters you can used to configure this module
    @Override
    protected SAMLConfigBean samlConfigBean() {
        return new SAMLConfigBeanBuilder()
                // (Required) assuming IdP's ADFS link is https://idp-adfs-server/adfs/ls ...
                .setAdfsHostName("idp-adfs-server")
                // (Required) keystore containing both Sp's public/private key and imported IdP's public certificate.
                .setKeyStoreResource(new DefaultResourceLoader().getResource("classpath:keystore.jks"))
                // (Required) keystore alias.
                .setKeystoreAlias("alias")
                // (Required) keystore password.
                .setKeystorePassword("secret")
                // (Required) where to redirect user if there's no saved request in session 
                // (ie: user gets logged in by clicking on `/saml/login` link).
                .setSuccessLoginDefaultUrl("/")
                // (Required) where to redirect user when logging out.
                .setSuccessLogoutUrl("/goodbye")
                // (Optional) Where to redirect user on failed login. This is probably not needed
                // because IdP should handle the failed login instead of returning back to Sp.
                // So, you probably don't need to set this.
                .setFailedLoginDefaultUrl(null)
                // (Optional) An opportunity to define user authorities or user properties either by cherry picking
                // from claims from IdP's SAML response or from other data sources
                .setUserDetailsService(new SAMLUserDetailsService() {
                    @Override
                    public Object loadUserBySAML(final SAMLCredential credential) throws UsernameNotFoundException {
                        return ...;
                    }
                })
                .createSAMLConfigBean();
    }

    // This configuration is not needed if your signature algorithm is SHA256withRSA and 
    // digest algorithm is SHA-256. However, if you are using different algorithm(s), then
    // add this bean with the correct algorithms.
    @Bean
    public static SAMLBootstrap samlBootstrap() {
        return new DefaultSAMLBootstrap("RSA",
                                        SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA512,
                                        SignatureConstants.ALGO_ID_DIGEST_SHA512);
    }

    // call `samlizedConfig(http)` first to redecorate `http` with SAML configuration
    // before configuring app specific HTTP security
    @Override
    protected void configure(final HttpSecurity http) throws Exception {
        samlizedConfig(http)
                .authorizeRequests().antMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated();
    }

    // call `samlizedConfig(web)` first to redecorate `web` with SAML configuration 
    // before configuring app specific web security
    @Override
    public void configure(final WebSecurity web) throws Exception {
        samlizedConfig(web).ignoring().antMatchers("/resources/**");
    }
}
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

