package com.marcuslull.springauthserver;

import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

@Component
public class AuthenticationEvent {
    // used with SecurityConfiguration.authenticationEventPublisher() to listen for authentication events

    @EventListener
    public void onSuccess(AuthenticationSuccessEvent successEvent) {
        System.out.println(successEvent);
    }

    @EventListener
    public void onFailure(AbstractAuthenticationFailureEvent failureEvent) {
        System.out.println(failureEvent);
    }
}
