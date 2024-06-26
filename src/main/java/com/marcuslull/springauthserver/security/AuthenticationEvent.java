package com.marcuslull.springauthserver.security;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

@Component
@Configuration
public class AuthenticationEvent {
    // used with SecurityConfiguration.authenticationEventPublisher() to listen for authentication events

    @Bean
    public AuthenticationEventPublisher authenticationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        // listener for authentication events
        return new DefaultAuthenticationEventPublisher(applicationEventPublisher);
    }

    @EventListener
    public void onSuccess(AuthenticationSuccessEvent successEvent) {
        System.out.println(successEvent);
    }

    @EventListener
    public void onFailure(AbstractAuthenticationFailureEvent failureEvent) {
        System.out.println(failureEvent);
    }
}
