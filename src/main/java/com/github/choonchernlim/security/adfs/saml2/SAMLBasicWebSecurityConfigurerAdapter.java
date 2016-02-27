package com.github.choonchernlim.security.adfs.saml2;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.security.saml.metadata.MetadataGeneratorFilter;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;

public abstract class SAMLBasicWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {

    @Autowired
    private SAMLEntryPoint samlEntryPoint;

    @Autowired
    private MetadataGeneratorFilter metadataGeneratorFilter;

    protected final HttpSecurity samlizedConfig(final HttpSecurity http) throws Exception {
        return http.httpBasic()
                .authenticationEntryPoint(samlEntryPoint)
                .and()
                .addFilterBefore(metadataGeneratorFilter, ChannelProcessingFilter.class);
    }
}
