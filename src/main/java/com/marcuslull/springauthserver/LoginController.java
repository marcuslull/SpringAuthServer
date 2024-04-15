package com.marcuslull.springauthserver;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LoginController {

    private final AuthenticationManager authenticationManager;
    // Example authentication with a controller rather than a filter - Storing manually
    // We need a context repository
    private final SecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();
    // We need the default strategy
    SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();
    // We need a context
    SecurityContext context = securityContextHolderStrategy.createEmptyContext();
    public LoginController(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @PostMapping("/api-login")
    public ResponseEntity<Authentication> apiLogin() {
        // disable form login and csrf for this to work
        return ResponseEntity.ok(SecurityContextHolder.getContext().getAuthentication());
    }

    @PostMapping("/manual-auth-storage")
    public ResponseEntity<Authentication> manual(@RequestBody LoginRequest loginRequest, HttpServletRequest request, HttpServletResponse response) {
        UsernamePasswordAuthenticationToken token = UsernamePasswordAuthenticationToken.unauthenticated(
                loginRequest.userName(), loginRequest.password()); // an unauthenticated login attempt
        Authentication authentication = authenticationManager.authenticate(token); // try and authenticate it
        context.setAuthentication(authentication); // add it to the context
        // explicit save context to session - default true - requires you to explicitly save to the session
        // here is how...
        securityContextHolderStrategy.setContext(context); // add the context to the strategy
        securityContextRepository.saveContext(context, request, response); // persist it to the session
        return ResponseEntity.ok(SecurityContextHolder.getContext().getAuthentication());
    }
}
