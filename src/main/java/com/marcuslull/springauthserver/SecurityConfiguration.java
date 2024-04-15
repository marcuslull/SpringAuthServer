package com.marcuslull.springauthserver;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.HeaderWriterLogoutHandler;
import org.springframework.security.web.context.DelegatingSecurityContextRepository;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.header.writers.ClearSiteDataHeaderWriter;
import org.springframework.security.web.session.HttpSessionEventPublisher;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception { // implement Filter or extend OncePerRequestFilter
        // Main configuration builder for the apps security posture. You can have more than one
        // inserted into the filter chain proxy
        http
//                .csrf(Customizer.withDefaults())
                // TODO: configure this properly
                .csrf(csrf -> csrf.disable()) // disables csrf for now so the api-login will work. Also disables the logout confirmation page


                // ----- BEGIN SESSION MANAGEMENT -----

                // sets the security context for the user. Determines what kind of persistence the context has across the
                // session or exceptions.
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

                // all requests must be authenticated with exceptions
                .authorizeHttpRequests(authorize -> authorize.requestMatchers("/manual-auth-storage", "/").permitAll()
                        .anyRequest().authenticated())

                // sets the types of authentication that will be available
                // adds my custom filter that will handle the api-login requests
                .addFilterBefore(new ApiLoginFilter(authenticationManager(userDetailsService(), passwordEncoder())), UsernamePasswordAuthenticationFilter.class)
                .httpBasic(Customizer.withDefaults()) // enables basic auth
                .formLogin(Customizer.withDefaults()); // enables an HTML form based login
//                .formLogin(form -> form.loginPage("/login").permitAll()); // specifying a custom login page

        return http.build();
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

    @Bean
    public UserDetailsService userDetailsService() {
        // Registers an in mem user details manager with test user, registers the Dao auth provider (via .withDefault...())
        // with auth manager.
        // User.withDefaultPasswordEncoder() is considered unsafe for production and is only intended for sample applications.
        UserDetails user = User.withDefaultPasswordEncoder() // only use this in non production env
                .username("user")
                .password("password")
                .roles("USER")
                .build();
        // building a user without withDefaultsPasswordEncoder(), password is stored as bcrypt hash
        UserDetails admin = User.builder()
                .username("admin")
                .password("{bcrypt}$2a$10$GRLdNijSQMUvl/au9ofL.eDwmoohzzS7.rmNSJZ.0FxO/BTk76klW") // 'password'
                .roles("USER", "ADMIN")
                .build();
        return new InMemoryUserDetailsManager(user, admin); // an in mem password storage
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        // standard password encoder
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        // listener for lifecycle events - keeps spring security up to date with session events
        // required for concurrent session control
        return new HttpSessionEventPublisher();
    }

    @Bean
    public AuthenticationEventPublisher authenticationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        // listener for authentication events
        return new DefaultAuthenticationEventPublisher(applicationEventPublisher);
    }

//    @Bean
//    DataSource dataSource() {
//        // For embedded data sources such as H2 you need to explicitly define the datasource.
//        // this is not needed for a traditional SQL DB
//        return new EmbeddedDatabaseBuilder()
//                .setType(H2) // embedded type
//                .addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION) // use the default DDL schema
//                .build();
//    }
//
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
