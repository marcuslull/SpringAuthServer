package com.marcuslull.springauthserver.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.marcuslull.springauthserver.model.LoginRequest;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class ApiLoginFilter extends OncePerRequestFilter {
    private final AuthenticationManager authenticationManager;

    public ApiLoginFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // authenticates via a JSON string when a user connects to /api-login
        // this is stateless, does not keep a context - add the auth to a Context and ContextHolderStrategy and repository for state
        AntPathMatcher pathMatcher = new AntPathMatcher();
        if (pathMatcher.match("/api/**", request.getRequestURI())) { //only login attempts at this path otherwise proceed regularly
            LoginRequest loginRequest = new ObjectMapper().readValue(request.getInputStream(), LoginRequest.class);
            Authentication authenticationRequest = UsernamePasswordAuthenticationToken.unauthenticated(loginRequest.userName(), loginRequest.password());
            Authentication authenticationResponse = this.authenticationManager.authenticate(authenticationRequest);
            if (authenticationResponse.isAuthenticated()) {
                SecurityContextHolder.getContext().setAuthentication(authenticationResponse);
            }
        }
        filterChain.doFilter(request, response);
    }
}
