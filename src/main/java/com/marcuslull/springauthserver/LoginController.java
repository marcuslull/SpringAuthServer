package com.marcuslull.springauthserver;

import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LoginController {

    @PostMapping("/api-login")
    public ResponseEntity<Authentication> apiLogin() {
        // disable form login and csrf for this to work
        return ResponseEntity.ok(SecurityContextHolder.getContext().getAuthentication());
    }
}
