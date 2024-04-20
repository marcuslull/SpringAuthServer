package com.marcuslull.springauthserver.security;

import jakarta.servlet.DispatcherType;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.HeaderWriterLogoutHandler;
import org.springframework.security.web.context.DelegatingSecurityContextRepository;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.security.web.csrf.XorCsrfTokenRequestAttributeHandler;
import org.springframework.security.web.header.writers.ClearSiteDataHeaderWriter;
import org.springframework.security.web.session.HttpSessionEventPublisher;

import java.io.IOException;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfiguration {

    // SECURITY FILTER CONFIGURATION
    @Bean
    @Order(1) // determines order of processing - multiple security filter chains is a valid config
    public SecurityFilterChain apiFilterChain(HttpSecurity http) throws Exception {
        http
                // This security filter chain only applies to routes that match the following...
                .securityMatcher("/api/**") // when defining an order always include a filter for context
                .csrf(csrf -> csrf.disable()) // disables csrf for now so the api-login will work. Also disables the logout confirmation page
                // Http sessions not maintained i.e. stateless - basically configures the SecurityContextRepository to use a NullSecurityContextRepository
                // may be used for api or Basic login attempts
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(authorize -> authorize
                        // authorization happens per dispatch not just per request so many endpoints will double authorize
                        // on the way in and on the return or errors. This prevents the double authorization
                        .dispatcherTypeMatchers(DispatcherType.FORWARD, DispatcherType.ERROR).permitAll()
                        // follow it all with the least privilege
                        .anyRequest().hasAuthority("ROLE_SUPER"))
                // adds my custom filter that will handle the api-login requests
                .addFilterBefore(new ApiLoginFilter(authenticationManager(userDetailsService(), passwordEncoder())), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception { // implement Filter or extend OncePerRequestFilter
        // Main configuration builder for the apps security posture. You can have more than one
        // inserted into the filter chain proxy
        http
                // ----- BEGIN CSRF CONFIG -----
                // ignore csrf configurations for the following dir. This seems to be finicky, I cant get wild cards to work, just exact matches.
                .csrf(csrf -> csrf.ignoringRequestMatchers("/manual-auth-storage"))
                .csrf(Customizer.withDefaults()) // default config explicitly defined - loads spring csrf protection defaults
                //  config explicitly defined - persists the csrf token in the session
                .csrf(csrf -> csrf.csrfTokenRepository(new HttpSessionCsrfTokenRepository())) // reads from: X-CSRF-TOKEN
                // JavaScript compatible settings - persists outside the session
//                .csrf(csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())) // reads from: X-XSRF-TOKEN, writes to a cookie named: XSRF-TOKEN
                // implement a custom token repo by implementing CsrfTokenRepository then...
//                .csrf(csrf -> csrf.csrfTokenRepository(new CustomCsrfTokenRepositoryName()))
                //  config explicitly defined - Handles csrf tokens and provides BREACH protection
                .csrf(csrf -> csrf.csrfTokenRequestHandler(new XorCsrfTokenRequestAttributeHandler())) // BREACH protection randomizes the token with each exchange
                // use a non-BREACH csrf handler
//                .csrf(csrf -> csrf.csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler()) // does not provide the BREACH protection
                // implement a custom token handler by implementing CsrfTokenRequestHandler
//                .csrf(csrf -> csrf.csrfTokenRequestHandler(new CustomCsrfTokenRequestHandlerName())

                // Integrating csrf with front-end apps
                // spring defaults to loading the token on unsafe HTTPS methods only.
//                XorCsrfTokenRequestAttributeHandler handler = new XorCsrfTokenRequestAttributeHandler(); // customize the handler
//                handler.setCsrfRequestAttributeName(null); // set the name to null, so it forces an activation every request
//                .csrf(csrf -> csrf.csrfTokenRequestHandler(handler)) // apply it as the handler
                // Single Page Applications, SPAs require special handling because only components are refreshed rather than the whole page
                // making .csrf handling occur when a request has an unsafe HTTP method. See documentation for configuration
                // different JS frameworks/libraries handle csrf tokens in different ways. See documentation for compatible configurations
                // disable csrf app wide - csrf protection not required for non-browser related traffic.
//                .csrf(csrf -> csrf.disable()) // Also disables the logout confirmation page
                // Multi-part uploads should include the csrf token in the (JS) header or (other) body. See docs for parsing token from body
                // ----- END CSRF CONFIG -----

                // ----- BEGIN HEADERS CONFIG -----
                // see documentation - there are a bunch of security header options spring provides by default that can be disabled or re-configured
                // consideration for header option should be given dependent on the type of app being secured
                // ----- END HEADERS CONFIG -----

                // ----- BEGIN SESSION MANAGEMENT -----
                // sets the security context for the user. Determines what kind of persistence the context has across the session or exceptions.
                .securityContext(securityContext -> securityContext
                        .securityContextRepository(
                                new DelegatingSecurityContextRepository( // container for multiple repos, can be omitted
                                        // There are a few of these contexts to choose from or custom
                                        new HttpSessionSecurityContextRepository(), // associates context with the user session
                                        new RequestAttributeSecurityContextRepository() // retains a reference to the context that can be used after the context has been cleared by an exception
//                                new NullSecurityContextRepository() // this one does not persist the context
                                )
                        ))
                // sets a custom repo for session auth info
//                .securityContext(securityContext -> securityContext.securityContextRepository(...)) // create a new SecurityContextRepository and pass it here
                // Http sessions not maintained i.e. stateless - basically configures the SecurityContextRepository to use a NullSecurityContextRepository
                // may be used for api or Basic login attempts
//                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // eager session creation
//                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.ALWAYS))
                // keeps concurrent user logins to 1. Must implement HttpSessionEventPublisher, see below
                .sessionManagement(session -> session.maximumSessions(1)) // a new login invalidates the old one
//                        .maxSessionsPreventsLogin(true)) // or, prevent a second attempt altogether
//                        .invalidateSessionUrl("/invalidSessionPage") // and send them somewhere
                // session fixation strategy, default is to newSession()
                .sessionManagement(session -> session.sessionFixation(sessionFixation -> sessionFixation.newSession()))
                // ----- END SESSION MANAGEMENT -----

                // ----- BEGIN LOGOUT CONFIG -----
                // logout auto operations: Invalidate session, Clear holder strategy, clear session repo, cleanup Remember me, clear csrf token, logout success event
                // Option to clear cookies on logout (.deleteCookies("JSESSIONID") doesnt always work)
                .logout(logout -> logout.addLogoutHandler(new HeaderWriterLogoutHandler(
                        new ClearSiteDataHeaderWriter(ClearSiteDataHeaderWriter.Directive.COOKIES))))
                // custom logout url - no need to specify a permitAll() for the URL as the logout filter comes before the authorize filter in the chain
//                .logout(logout -> logout.logoutUrl("/someUrl"))
                // and a custom logout success url
//                .logout(logout -> logout.logoutSuccessUrl("/someUrl").permitAll()) // here you do need a .permitAll()
                // customizing the cleanup
//                .logout(logout -> logout.addLogoutHandler(...)) // a custom handler implementing LogoutHandler
                // ----- END LOGOUT CONFIG -----

                // ----- BEGIN AUTHORIZATION CONFIG -----
                .authorizeHttpRequests(authorize -> authorize
                        // matching rules
                        .requestMatchers("/", "/manual-auth-storage", "/static/images/**").permitAll() // authenticating on /manual... requires csrf disable
                        .requestMatchers("/another-page").hasAuthority("ROLE_ADMIN")
//                        .requestMatchers("/resource/**").hasAuthority("ROLE_ADMIN") // everything under /resources/
//                        .requestMatchers("/resource/{name}").access(
//                                new WebExpressionAuthorizationManager("#name == authentication.name")) // path variable used to authorize principal to their own resource
//                        .requestMatchers(HttpMethod.GET).hasAuthority("ROLE_READ") //matching on HttpMethods
//                        .requestMatchers(HttpMethod.POST).hasAuthority("ROLE_WRITE")
                        // authorization happens per dispatch not just per request so many endpoints will double authorize
                        // on the way in and on the return or errors. This prevents the double authorization
                        .dispatcherTypeMatchers(DispatcherType.FORWARD, DispatcherType.ERROR).permitAll()
                        //custom matchers
//                        RequestMatcher printView = request -> request.getParameter("print") != null;
//                        .requestMatchers(printView).hasAuthority("ROLE_PRINT")
                        // follow it all with the least privilege
                        .anyRequest().authenticated())
                // ----- END AUTHORIZATION CONFIG -----

                // handling access denied messages
                .exceptionHandling(exceptionHandling -> exceptionHandling.accessDeniedPage("/access-denied"))
                // sets the types of authentication that will be available
                .httpBasic(Customizer.withDefaults()) // enables basic auth
                .formLogin(Customizer.withDefaults()) // enables an HTML form based login
//                .formLogin(form -> form.loginPage("/login").permitAll()); // specifying a custom login page

                // adding a custom filter after all other filters
                .addFilterAfter(new AnotherFilter(), AuthorizationFilter.class);
        return http.build();
    }


    // AUTHENTICATION CONFIGURATION
    @Bean
    public UserDetailsService userDetailsService() {
        // Registers an in mem user details manager with test user, registers the Dao auth provider (via .withDefault...())
        // with auth manager.
        // User.withDefaultPasswordEncoder() is considered unsafe for production and is only intended for sample applications.
        UserDetails guest = User.withDefaultPasswordEncoder() // only use this in non production env
                .username("guest")
                .password("password")
                .roles("GUEST")
                .build();
        UserDetails user = User.withDefaultPasswordEncoder() // only use this in non production env
                .username("user")
                .password("password")
                .roles("USER")
                .build();
        // building a user without withDefaultsPasswordEncoder(), password is stored as bcrypt hash
        UserDetails superUser = User.builder()
                .username("super")
                .password("{bcrypt}$2a$10$GRLdNijSQMUvl/au9ofL.eDwmoohzzS7.rmNSJZ.0FxO/BTk76klW") // 'password'
                .roles("SUPER")
                .build();
        UserDetails admin = User.builder()
                .username("admin")
                .password("{bcrypt}$2a$10$GRLdNijSQMUvl/au9ofL.eDwmoohzzS7.rmNSJZ.0FxO/BTk76klW") // 'password'
                .roles("ADMIN")
                .build();
        return new InMemoryUserDetailsManager(guest, user, superUser, admin); // an in mem password storage
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        // standard password encoder
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        // only required for customization - this will normally be created on its own using the DaoAuthenticationProvider
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService);
        authenticationProvider.setPasswordEncoder(passwordEncoder);
//        // A customization to retain credentials for keeping a session of some sort
//        ProviderManager providerManager = new ProviderManager(authenticationProvider);
//        providerManager.setEraseCredentialsAfterAuthentication(false);
        return new ProviderManager(authenticationProvider);
    }


    // AUTHORITY CONFIGURATION
    @Bean
    static RoleHierarchy roleHierarchy() {
        // configuring authorization role hierarchy. Each super role will have lower reachable authorities
        // this is a custom config and is optional
        RoleHierarchyImpl hierarchy = new RoleHierarchyImpl();
        // ADMIN has SUPER, USER, and GUEST roles when evaluated against an Authorization manager
        hierarchy.setHierarchy("ROLE_ADMIN > ROLE_SUPER > ROLE_USER > ROLE_GUEST");
        return hierarchy;
    }

    @Bean
    static MethodSecurityExpressionHandler methodSecurityExpressionHandler(RoleHierarchy roleHierarchy) {
        // applies the above role hierarchy to method level security
        DefaultMethodSecurityExpressionHandler expressionHandler = new DefaultMethodSecurityExpressionHandler();
        expressionHandler.setRoleHierarchy(roleHierarchy);
        return expressionHandler;
    }


    // CONCURRENT SESSION DETECTION
    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        // listener for lifecycle events - keeps spring security up to date with session events
        // required for concurrent session control
        return new HttpSessionEventPublisher();
    }



    // HTTP FIREWALL CONFIGURATION
    // this normalizes all URL paths that come into the server. Spec allows for non-standard path parameters in the URL, this could be bad
    // So, for example, an original request path of /secure;hack=1/somefile.html;hack=2 is returned as /secure/somefile.html.
    // here are some exceptions that could be made...

//    @Bean
//    public StrictHttpFirewall httpFirewall() {
//        // some legit system could make use out of ; in the path
//        StrictHttpFirewall firewall = new StrictHttpFirewall();
//        firewall.setAllowSemicolon(true);
//        return firewall;
//    }

//    @Bean
//    public StrictHttpFirewall httpFirewall() {
//        // limiting HTTP methods
//        StrictHttpFirewall firewall = new StrictHttpFirewall();
//        firewall.setAllowedHttpMethods(Arrays.asList("GET", "POST"));
//        return firewall;
//    }

//    @Bean
//    public StrictHttpFirewall httpFirewall() {
//        // allow non-standard header names, values or parameter values
//        StrictHttpFirewall firewall = new StrictHttpFirewall();
//        firewall.setAllowedHeaderNames((header) -> true);
//        firewall.setAllowedHeaderValues((header) -> true);
//        firewall.setAllowedParameterNames((parameter) -> true);
//        return firewall;
//    }



    //CUSTOM AUTHORIZATION PREFIX CONFIGURATION
//    @Bean
//    static GrantedAuthorityDefaults grantedAuthorityDefaults() {
//        // define a custom prefix for authorization
//        // role-based authorization uses ROLE_ as a prefix
//        return new GrantedAuthorityDefaults("CUSTOMPREFIX_");
//    }


    // EMBEDDED DATASOURCE CONFIGURATION
//    @Bean
//    DataSource dataSource() {
//        // For embedded data sources such as H2 you need to explicitly define the datasource.
//        // this is not needed for a traditional SQL DB
//        return new EmbeddedDatabaseBuilder()
//                .setType(H2) // embedded type
//                .addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION) // use the default DDL schema
//                .build();
//    }

//    @Bean
//    UserDetailsManager users(DataSource dataSource) {
//        // if using an embedded DB solution this is how you would specify the datasource
//        UserDetails user = User.builder()
//                .username("user")
//                .password("{bcrypt}$2a$10$GRLdNijSQMUvl/au9ofL.eDwmoohzzS7.rmNSJZ.0FxO/BTk76klW") // 'password'
//                .roles("USER")
//                .build();
//        UserDetails admin = User.builder()
//                .username("admin")
//                .password("{bcrypt}$2a$10$GRLdNijSQMUvl/au9ofL.eDwmoohzzS7.rmNSJZ.0FxO/BTk76klW") // 'password'
//                .roles("USER", "ADMIN")
//                .build();
//        JdbcUserDetailsManager users = new JdbcUserDetailsManager(dataSource);
//        users.createUser(user);
//        users.createUser(admin);
//        return users;
//    }
}
