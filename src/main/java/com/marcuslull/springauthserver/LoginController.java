package com.marcuslull.springauthserver;

import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LoginController {

    private final AuthenticationManager authenticationManager;

    public LoginController(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @PostMapping("/api-login")
    public ResponseEntity<Authentication> apiLogin(@RequestBody LoginRequest loginRequest) {
        // disable form login and csrf for this to work
        Authentication authenticationRequest = UsernamePasswordAuthenticationToken.unauthenticated(loginRequest.userName(), loginRequest.password());
        Authentication authenticationResponse = this.authenticationManager.authenticate(authenticationRequest);
        return ResponseEntity.ok(authenticationResponse);
    }
}
