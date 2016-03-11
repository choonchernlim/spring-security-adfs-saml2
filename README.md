# spring-security-adfs-saml2 [![Build Status](https://travis-ci.org/choonchernlim/spring-security-adfs-saml2.svg?branch=master)](https://travis-ci.org/choonchernlim/spring-security-adfs-saml2)

Spring Security module for service provider (Sp) to authenticate against identity provider's (IdP) ADFS using SAML2 protocol.

How this module is configured:-

* `HTTP-Redirect` binding for sending SAML messages to IdP.
* Default authentication method is user/password using IdP's form login page. 
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
  <version>0.3.1</version>
</dependency>
```

## Prerequisites

* Sp must use HTTPS protocol.
* Java’s default keysize is limited to 128-bit key due to US export laws and a few countries’ import laws. So, Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files must be installed to allow larger key size, such as 256-bit key.
* Keystore must contain both Sp's public/private keys and imported IdP's public certificate. 
    * Sp's public/private keys - to generate digital signature before sending SAML messages to IdP.
    * IdP's public certificate - to verify IdP's SAML messages to prevent man-in-the-middle attack.
    * To import IdP's public certificate into keystore:-
        * `keytool -importcert -file idp-adfs-server.cer -keystore keystore.jks -alias idp-adfs-server`

## Usage 

```java
// Create a Java-based Spring configuration that extends SAMLWebSecurityConfigurerAdapter.
@Configuration
@EnableWebSecurity
class AppSecurityConfig extends SAMLWebSecurityConfigurerAdapter {

    // See `SAMLConfigBean Properties` section below for more info. 
    @Override
    protected SAMLConfigBean samlConfigBean() {
        return new SAMLConfigBeanBuilder()
                .setSpMetadataBaseUrl("https://localhost:8443/my-app")
                .setAdfsHostName("idp-adfs-server")
                .setKeystoreResource(new DefaultResourceLoader().getResource("classpath:keystore.jks"))
                .setKeystorePassword("storepass")
                .setKeystoreAlias("alias")
                .setKeystorePrivateKeyPassword("keypass")
                .setSuccessLoginDefaultUrl("/")
                .setSuccessLogoutUrl("/goodbye")
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

    // call `samlizedConfig(http)` first to decorate `http` with SAML configuration
    // before configuring app specific HTTP security
    @Override
    protected void configure(final HttpSecurity http) throws Exception {
        samlizedConfig(http)
                .authorizeRequests().antMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated();
    }

    // call `samlizedConfig(web)` first to decorate `web` with SAML configuration 
    // before configuring app specific web security
    @Override
    public void configure(final WebSecurity web) throws Exception {
        samlizedConfig(web).ignoring().antMatchers("/resources/**");
    }
}
```

## SAMLConfigBean Properties
 
`SAMLConfigBean` stores app-specific security configuration.

|Property                   |Required? |Description                                                                                               |
|---------------------------|----------|----------------------------------------------------------------------------------------------------------|
|spMetadataBaseUrl          |Yes       |Sp's metadata base URL with format `https://server(:port)/contextPath` for constructing SAML endpoints (ex: `/saml/**`). This configuration is important to prevent servers doing SSL termination from generating wrong endpoints.|
|adfsHostName               |Yes       |ADFS host name without HTTPS protocol.<p>If ADFS link is `https://idp-adfs-server/adfs/ls`, the value should be `idp-adfs-server`.|
|keystoreResource           |Yes       |App's keystore containing its public/private key and ADFS' certificate with public key.                   |
|keystorePassword           |Yes       |Password to access app's keystore.                                                                        |
|keystoreAlias              |Yes       |Alias of app's public/private key pair.                                                                   |
|keystorePrivateKeyPassword |Yes       |Password to access app's private key.                                                                     |
|successLoginDefaultUrl     |Yes       |Where to redirect user on successful login if no saved request is found in the session.                   |
|successLogoutUrl           |Yes       |Where to redirect user on successful logout.                                                              |
|failedLoginDefaultUrl      |No        |Where to redirect user on failed login. This value is set to null, which returns 401 error code on failed login. But, in theory, this will never be used because IdP will handled the failed login on IdP login page.<br/><br/>Default is `''`, which return 401 error code.|
|samlUserDetailsService     |No        |For configuring user authorities (ex: `ROLE_*`) if needed.<br/><br/>Default is `null`.                                       |
|authnContexts              |No        |Determine what authentication methods to use. To use the order of authentication methods defined by IdP, set as empty set. To enable Windows Integrated Auth (WIA), use `CustomAuthnContext.WINDOWS_INTEGRATED_AUTHN_CTX`.<br/><br/>Default is `AuthnContext.PASSWORD_AUTHN_CTX` where IdP login page is displayed to obtain user/password.|


## Important SAML Endpoints

There are several SAML processing endpoints, but these are the ones you probably care:-

|Endpoint              |Description                                                                                                                             |
|----------------------|----------------------------------------------------------------------------------------------------------------------------------------|
|`/saml/login`         |Initiates login process between Sp and IdP. Upon successful login, user will be redirected to `SAMLConfigBean.successLoginDefaultUrl`.  |
|`/saml/logout`        |Initiates logout process between Sp and IdP. Upon successful logout, user will be redirected to `SAMLConfigBean.successLogoutUrl`.      |
|`/saml/metadata`      |Returns Sp metadata. IdP may need this link to register Sp on ADFS.                                                                     |

## Relevant Links

* [Travis CI Reports](https://travis-ci.org/choonchernlim/spring-security-adfs-saml2)
* [Maven Site](https://choonchernlim.github.io/spring-security-adfs-saml2/project-info.html)

Learn about my pains and lessons learned while building this module.

* [Replacing SHA-1 with SHA-256 on Signature and Digest Algorithms](http://myshittycode.com/2016/02/23/spring-security-saml-replacing-sha-1-with-sha-256-on-signature-and-digest-algorithms/)
* [Handling IdP’s Public Certificate When Loading Metadata Over HTTPS](http://myshittycode.com/2016/02/19/spring-security-saml-handling-idps-public-certificate-when-loading-metadata-over-https/)
* [Configuring Binding for Sending SAML Messages to IdP](http://myshittycode.com/2016/02/18/spring-security-saml-configuring-binding-for-sending-saml-messages-to-idp/)
* [Java + SAML: Illegal Key Size](http://myshittycode.com/2016/02/18/java-saml-illegal-key-size/)
