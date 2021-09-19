/**
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE in the project root for
 * license information.
 */
package com.microsoft.azure.spring.autoconfigure.b2c;

  <<<<<<< release/2.3.2
import com.microsoft.azure.telemetry.TelemetrySender;
import lombok.NonNull;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnResource;
  =======
import com.microsoft.azure.telemetry.TelemetryData;
import com.microsoft.azure.telemetry.TelemetryProxy;
import lombok.NonNull;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
  >>>>>>> aad-b2c-integration
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
  <<<<<<< release/2.3.2
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;
import org.springframework.util.StringUtils;

import javax.annotation.PostConstruct;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.microsoft.azure.spring.autoconfigure.b2c.AADB2CProperties.PREFIX;
import static com.microsoft.azure.spring.autoconfigure.b2c.AADB2CProperties.USER_FLOW_SIGN_UP_OR_SIGN_IN;
import static com.microsoft.azure.telemetry.TelemetryData.*;

@Configuration
@ConditionalOnWebApplication
@ConditionalOnResource(resources = "classpath:aadb2c.enable.config")
@ConditionalOnProperty(
        prefix = PREFIX,
        value = {
                "tenant",
                "client-id",
                "client-secret",
                "reply-url",
                USER_FLOW_SIGN_UP_OR_SIGN_IN
        }
)
@EnableConfigurationProperties(AADB2CProperties.class)
public class AADB2CAutoConfiguration {

    private final ClientRegistrationRepository repository;

    private final AADB2CProperties properties;

    public AADB2CAutoConfiguration(@NonNull ClientRegistrationRepository repository,
                                   @NonNull AADB2CProperties properties) {
        this.repository = repository;
        this.properties = properties;
  =======
import org.springframework.util.ClassUtils;

import java.util.HashMap;
import java.util.Map;

import static com.microsoft.azure.spring.autoconfigure.b2c.AADB2CProperties.*;

@Configuration
@ConditionalOnWebApplication
@ConditionalOnProperty(prefix = AADB2CProperties.PREFIX, value = {
        "tenant",
        "client-id",
        LOGOUT_SUCCESS_URL,
        POLICY_SIGN_UP_OR_SIGN_IN_NAME,
        POLICY_SIGN_UP_OR_SIGN_IN_REPLY_URL
})
@EnableConfigurationProperties(AADB2CProperties.class)
public class AADB2CAutoConfiguration {

    private final AADB2CProperties properties;

    public AADB2CAutoConfiguration(@NonNull AADB2CProperties properties) {
        this.properties = properties;

        trackCustomEvent(properties.isAllowTelemetry());
    }

    private void trackCustomEvent(boolean isAllowTelemetry) {
        if (isAllowTelemetry) {
            final TelemetryProxy telemetryProxy = new TelemetryProxy(true);
            final Map<String, String> events = new HashMap<>();

            events.put(TelemetryData.SERVICE_NAME, getClass().getPackage().getName().replaceAll("\\w+\\.", ""));
            events.put(TelemetryData.TENANT_NAME, properties.getTenant());

            telemetryProxy.trackEvent(ClassUtils.getUserClass(getClass()).getSimpleName(), events);
        }
  >>>>>>> aad-b2c-integration
    }

    @Bean
    @ConditionalOnMissingBean
  <<<<<<< release/2.3.2
    public AADB2CAuthorizationRequestResolver b2cOAuth2AuthorizationRequestResolver() {
        return new AADB2CAuthorizationRequestResolver(repository, properties.getUserFlows().getPasswordReset());
  =======
    public AADB2CEntryPoint aadB2CEntryPoint() {
        return new AADB2CEntryPoint(properties);
  >>>>>>> aad-b2c-integration
    }

    @Bean
    @ConditionalOnMissingBean
  <<<<<<< release/2.3.2
    public AADB2CLogoutSuccessHandler b2cLogoutSuccessHandler() {
  =======
    public AADB2CLogoutSuccessHandler aadB2CLogoutSuccessHandler() {
  >>>>>>> aad-b2c-integration
        return new AADB2CLogoutSuccessHandler(properties);
    }

    @Bean
    @ConditionalOnMissingBean
  <<<<<<< release/2.3.2
    public AADB2COidcLoginConfigurer b2cLoginConfigurer(AADB2CLogoutSuccessHandler handler,
                                                        AADB2CAuthorizationRequestResolver resolver) {
        return new AADB2COidcLoginConfigurer(properties, handler, resolver);
    }

    @PostConstruct
    private void sendTelemetry() {
        if (properties.isAllowTelemetry()) {
            final Map<String, String> events = new HashMap<>();
            final TelemetrySender sender = new TelemetrySender();

            events.put(SERVICE_NAME, getClassPackageSimpleName(AADB2CAutoConfiguration.class));
            events.put(TENANT_NAME, properties.getTenant());

            sender.send(ClassUtils.getUserClass(getClass()).getSimpleName(), events);
        }
    }

    @Configuration
    @ConditionalOnResource(resources = "classpath:aadb2c.enable.config")
    @ConditionalOnProperty(prefix = PREFIX, value = "oidc-enabled", havingValue = "true", matchIfMissing = true)
    public static class AADB2COidcAutoConfiguration {

        private final AADB2CProperties properties;

        public AADB2COidcAutoConfiguration(@NonNull AADB2CProperties properties) {
            this.properties = properties;
        }

        private void addB2CClientRegistration(@NonNull List<ClientRegistration> registrations, String userFlow) {
            if (StringUtils.hasText(userFlow)) {
                registrations.add(b2cClientRegistration(userFlow));
            }
  =======
    public AADB2CFilterScenarioHandlerChain aadB2CFilterScenarioChain() {
        return new AADB2CFilterScenarioHandlerChain();
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = AADB2CProperties.PREFIX, value = {
            POLICY_PROFILE_EDIT_NAME,
            POLICY_PROFILE_EDIT_REPLY_URL,
            PROFILE_EDIT_URL
    })
    public AADB2CFilterProfileEditHandler profileEditHandler(AADB2CFilterScenarioHandlerChain handlerChain) {
        final AADB2CFilterProfileEditHandler handler = new AADB2CFilterProfileEditHandler(properties);

        handlerChain.addHandler(handler);

        return handler;
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = AADB2CProperties.PREFIX, value = {
            POLICY_PASSWORD_RESET_NAME,
            POLICY_PASSWORD_RESET_REPLY_URL,
            PASSWORD_RESET_URL
    })
    public AADB2CFilterPasswordResetHandler passwordResetHandler(AADB2CFilterScenarioHandlerChain handlerChain) {
        final AADB2CFilterPasswordResetHandler handler = new AADB2CFilterPasswordResetHandler(properties);

        handlerChain.addHandler(handler);

        return handler;
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(AADB2CFilterPasswordResetHandler.class)
    public AADB2CFilterForgotPasswordHandler forgotPasswordHandler(AADB2CFilterScenarioHandlerChain handlerChain) {
        final AADB2CFilterForgotPasswordHandler handler = new AADB2CFilterForgotPasswordHandler(properties);

        handlerChain.addHandler(handler);

        return handler;
    }

    @Configuration
    public static class OpenIdSessionAutoConfiguration {

        private final AADB2CProperties b2cProperties;

        private final AADB2CFilterScenarioHandlerChain handlerChain;

        public OpenIdSessionAutoConfiguration(@NonNull AADB2CProperties b2cProperties,
                                              @NonNull AADB2CFilterScenarioHandlerChain handlerChain) {
            this.b2cProperties = b2cProperties;
            this.handlerChain = handlerChain;
  >>>>>>> aad-b2c-integration
        }

        @Bean
        @ConditionalOnMissingBean
  <<<<<<< release/2.3.2
        public ClientRegistrationRepository clientRegistrationRepository() {
            final List<ClientRegistration> registrations = new ArrayList<>();

            addB2CClientRegistration(registrations, properties.getUserFlows().getSignUpOrSignIn());
            addB2CClientRegistration(registrations, properties.getUserFlows().getProfileEdit());
            addB2CClientRegistration(registrations, properties.getUserFlows().getPasswordReset());

            return new InMemoryClientRegistrationRepository(registrations);
        }

        private ClientRegistration b2cClientRegistration(String userFlow) {
            Assert.hasText(userFlow, "User flow should contains text.");

            return ClientRegistration.withRegistrationId(userFlow) // Use flow as registration Id.
                    .clientId(properties.getClientId())
                    .clientSecret(properties.getClientSecret())
                    .clientAuthenticationMethod(ClientAuthenticationMethod.POST)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .redirectUriTemplate(properties.getReplyUrl())
                    .scope(properties.getClientId(), "openid")
                    .authorizationUri(AADB2CURL.getAuthorizationUrl(properties.getTenant()))
                    .tokenUri(AADB2CURL.getTokenUrl(properties.getTenant(), userFlow))
                    .jwkSetUri(AADB2CURL.getJwkSetUrl(properties.getTenant(), userFlow))
                    .userNameAttributeName("name")
                    .clientName(userFlow)
                    .build();
  =======
        public AADB2CFilterPolicyReplyHandler policyReplyHandler() {
            final AADB2CFilterPolicyReplyHandler policyReply = new AADB2CFilterPolicyReplyHandler(b2cProperties);

            handlerChain.addHandler(policyReply);

            return policyReply;
        }

        @Bean
        @ConditionalOnMissingBean
        public AADB2CFilter aadB2CFilter() {
            return new AADB2CFilter(handlerChain);
  >>>>>>> aad-b2c-integration
        }
    }
}
