package com.secure.exchange.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.*;
import java.util.stream.Collectors;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity // Enables @PreAuthorize if we need it later
public class SecurityConfig {

        private final RateLimitFilter rateLimitFilter;

        public SecurityConfig(RateLimitFilter rateLimitFilter) {
                this.rateLimitFilter = rateLimitFilter;
        }

        @Bean
        public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
                http
                                // 0. Rate Limiting (DoS Protection) - Must be first!
                                .addFilterBefore(rateLimitFilter,
                                                org.springframework.security.web.access.intercept.AuthorizationFilter.class)

                                // 1. Enable CORS (Cross-Origin Resource Sharing)
                                .cors(cors -> cors.configurationSource(corsConfigurationSource()))

                                // 2. Disable CSRF (Not needed for API/Stateless architecture)
                                .csrf(csrf -> csrf.disable())

                                // 3. Protect all endpoints
                                .authorizeHttpRequests(auth -> auth
                                                // ALLOW ws handshake (Auth is handled at STOMP Protocol level in
                                                // WebSocketConfig)
                                                .requestMatchers("/ws/**").permitAll()
                                                // ALLOW Swagger UI & OpenAPI Docs
                                                .requestMatchers("/v3/api-docs/**", "/swagger-ui/**",
                                                                "/swagger-ui.html")
                                                .permitAll()
                                                .anyRequest().authenticated())

                                // 4. Configure as OAuth2 Resource Server with custom JWT converter
                                .oauth2ResourceServer(
                                                oauth2 -> oauth2.jwt(jwt -> jwt.jwtAuthenticationConverter(
                                                                jwtAuthenticationConverter())))

                                // 5. HTTP Headers (CSP + HSTS)
                                .headers(headers -> headers
                                                .contentSecurityPolicy(csp -> csp
                                                                .policyDirectives(
                                                                                "default-src 'self' blob: data:; script-src 'self' 'unsafe-inline'; connect-src 'self' https://localhost:8443 wss://localhost:8443 https://localhost:8444; frame-ancestors 'none';"))
                                                .httpStrictTransportSecurity(hsts -> hsts
                                                                .includeSubDomains(true)
                                                                .maxAgeInSeconds(31536000))
                                                .permissionsPolicy(permissions -> permissions
                                                                .policy("camera=(), microphone=(), geolocation=(), payment=()")));

                return http.build();
        }

        /**
         * Extracts roles from Keycloak JWT and maps them to Spring Security
         * authorities.
         * Keycloak stores roles in: jwt.realm_access.roles[]
         */
        @Bean
        public JwtAuthenticationConverter jwtAuthenticationConverter() {
                JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
                converter.setJwtGrantedAuthoritiesConverter(jwt -> {
                        // Extract realm roles from Keycloak JWT
                        Map<String, Object> realmAccess = jwt.getClaim("realm_access");
                        Collection<String> roles = new ArrayList<>();

                        if (realmAccess != null && realmAccess.get("roles") instanceof List) {
                                roles = (List<String>) realmAccess.get("roles");
                        }

                        // Convert to Spring Security authorities with ROLE_ prefix
                        return roles.stream()
                                        .map(role -> new SimpleGrantedAuthority("ROLE_" + role.toUpperCase()))
                                        .collect(Collectors.toList());
                });

                return converter;
        }

        @Bean
        CorsConfigurationSource corsConfigurationSource() {
                CorsConfiguration configuration = new CorsConfiguration();

                // Allow both HTTP and HTTPS for development
                // Allow ONLY HTTPS for development (Zero Trust Network)
                configuration.setAllowedOrigins(List.of(
                                "https://localhost:5173"));

                configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
                configuration.setAllowedHeaders(List.of("Authorization", "Content-Type"));
                configuration.setAllowCredentials(true);

                UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
                source.registerCorsConfiguration("/**", configuration);
                return source;
        }
}
