package com.marcuslull.springauthserver.security;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.event.EventListener;
import org.springframework.security.authorization.AuthorizationEventPublisher;
import org.springframework.security.authorization.SpringAuthorizationEventPublisher;
import org.springframework.security.authorization.event.AuthorizationDeniedEvent;
import org.springframework.security.authorization.event.AuthorizationGrantedEvent;
import org.springframework.stereotype.Component;

@Component
@Configuration
public class AuthorizationEvent {

    @Bean
    public AuthorizationEventPublisher authorizationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        // listener for authorization events
        return new SpringAuthorizationEventPublisher(applicationEventPublisher);
    }

    @EventListener
    public void onFailure(AuthorizationDeniedEvent deniedEvent) {
        System.out.println(deniedEvent);
    }

    @EventListener
    public void onSuccess(AuthorizationGrantedEvent grantedEvent) {
        // may need to filter this one it is noisy!
        System.out.println(grantedEvent);
    }
}
