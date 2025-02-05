package com.yelm.jwtlogin.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.yelm.jwtlogin.blacklist.TokenBlacklistService;
import com.yelm.jwtlogin.jwt.*;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    @Value("${cors.allowed-origins}")
    private String allowedOrigins;

    // authenticationManager() paramerter
    private final AuthenticationConfiguration authenticationConfiguration;

    private final JWTUtil jwtUtil;

    private final TokenBlacklistService blacklistService;

    @Autowired
    private final ObjectMapper objectMapper;

    @Bean
    public PasswordEncoder passwordEncoder() {
        Map<String, PasswordEncoder> encoders = new HashMap<>();
        encoders.put("bcrypt", new BCryptPasswordEncoder());
        encoders.put("sha256", new org.springframework.security.crypto.password.StandardPasswordEncoder());

        return new DelegatingPasswordEncoder("sha256", encoders);
    }

    // Add AuthenticationManager as `@Bean`
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, CorsConfigurationSource corsConfigurationSource) throws Exception {
        // CORS
        http
                .cors(
                        corsConfigurer ->
                                corsConfigurer.configurationSource(corsConfigurationSource()));

        // csrf disable
        http
                .csrf((auth) -> auth.disable());

        // Form Login disable
        http
                .formLogin((auth) -> auth.disable());

        // http basic Authentication disable
        http
                .httpBasic((auth) -> auth.disable());

        // Authenticate
        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/login", "/", "/join", "/reissue").permitAll()
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated());

        // JWT filter
        http
                .addFilterBefore(new JWTFilter(jwtUtil, blacklistService), LoginFilter.class);

        http
                .addFilterAt(
                        new LoginFilter(authenticationManager(authenticationConfiguration),
                                jwtUtil,
                                objectMapper),
                        UsernamePasswordAuthenticationFilter.class);

        // Logout
        http
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .addLogoutHandler(new JwtLogoutHandler(blacklistService))
                        .logoutSuccessHandler(new JwtLogoutSuccessHandler())
                );

        // Session
        http
                .sessionManagement((session) -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));


        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList(allowedOrigins));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PATCH", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);

        configuration.setExposedHeaders(Collections.singletonList("Authorization"));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

}