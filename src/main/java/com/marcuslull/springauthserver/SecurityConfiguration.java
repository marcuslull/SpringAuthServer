package com.marcuslull.springauthserver;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
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
import org.springframework.security.web.context.DelegatingSecurityContextRepository;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception { // implement Filter or extend OncePerRequestFilter
        // Main configuration builder for the apps security posture. You can have more than one
        // inserted into the filter chain proxy
        http
//                .csrf(Customizer.withDefaults())
                .csrf(csrf -> csrf.disable()) // disables csrf for now so the api-login will work TODO: configure this properly

                // sets the security context for the user. Determines what kind of persistence the context has across the
                // session or exceptions.
                .securityContext(securityContext -> securityContext.securityContextRepository(
                        new DelegatingSecurityContextRepository( // container for multiple repos, can be omitted
                                // There are a few of these contexts to choose from or custom
                                new HttpSessionSecurityContextRepository(), // associates context with the user session
                                new RequestAttributeSecurityContextRepository() // retains a reference to the context that can be used after the context has been cleared by an exception
//                                new NullSecurityContextRepository() // this one does not persist the context
                        )
                ))

                // all requests must be authenticated
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())

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
