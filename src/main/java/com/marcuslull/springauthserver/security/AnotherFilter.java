package com.marcuslull.springauthserver.security;

import jakarta.servlet.AsyncContext;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class AnotherFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        // getting the current users basic info or anonymous
        System.out.println("Current user: " + request.getRemoteUser()); // anonymous is null
        System.out.println("Current authentication: " + request.getUserPrincipal()); // anonymous is null
        System.out.println("Is admin?: " + request.isUserInRole("ADMIN"));

        // propagate the security context to a new threads context
        // example async that prints the current authority
        final AsyncContext async = request.startAsync(); // async wrapper for a servlet request
        async.start(new Runnable() { // start the new thread
            @Override
            public void run() {
                // Do things here...
                Authentication authentication = SecurityContextHolder.getContext().getAuthentication(); // gets the authentication from the context
                System.out.println("Async context authentication token: " + authentication);
                async.complete(); // closes the async thread
            }
        });

        filterChain.doFilter(request, response);
    }
}
