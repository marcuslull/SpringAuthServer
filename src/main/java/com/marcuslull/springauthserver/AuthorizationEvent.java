package com.marcuslull.springauthserver;

import org.springframework.context.event.EventListener;
import org.springframework.security.authorization.event.AuthorizationDeniedEvent;
import org.springframework.security.authorization.event.AuthorizationGrantedEvent;
import org.springframework.stereotype.Component;

@Component
public class AuthorizationEvent {
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
