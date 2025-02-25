package com.sslcommerz.payment_gateway.websecurity;

import com.sslcommerz.payment_gateway.repository.TokenRepository;
import com.sslcommerz.payment_gateway.service.UserService;
import com.sslcommerz.payment_gateway.websecurity.jwt.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class SpringSecurity {

    @Autowired
    private UserService userService;

    @Autowired
    private JwtAuthenticationFilter authenticationFilter;


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return
                http
                        .csrf(AbstractHttpConfigurer::disable)
                        .cors(Customizer.withDefaults())
                        .authorizeHttpRequests(
                                req ->
                                        req.requestMatchers("/login", "/register", "/images/**","/active/**")
                                                .permitAll()

                                                .requestMatchers("/api/hotel/save")
                                                .hasAnyAuthority("HOTEL")

                                                .requestMatchers("/api/hotel/")
                                                .hasAnyAuthority("USER","ADMIN","HOTEL")

                                                .requestMatchers("/api/hotel/**")
                                                .hasAuthority("ADMIN")
                        )
                        .userDetailsService(userService)
                        .sessionManagement(
                                session -> session
                                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                        )
                        .addFilterBefore(authenticationFilter, UsernamePasswordAuthenticationFilter.class)
                        .build();

    }

    @Bean
    public PasswordEncoder encoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();

    }


}




