package com.example.scg.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

@RequiredArgsConstructor
@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final AuthenticationExceptionEntryPoint authenticationExceptionEntryPoint;
    /*
    security 6.1.0부터 메서드 체이닝 지양, 람다식 권장
     */

    @Bean
    public SecurityWebFilterChain filterChain(ServerHttpSecurity http) {
        return http
                .authorizeExchange(authorizeExchangeSpec -> // 경로에 대한 권한 설정
                        authorizeExchangeSpec
                                .pathMatchers("/auth/**").permitAll()
                                .pathMatchers("/admin/**").hasAuthority("admin")
                                .anyExchange().authenticated()
                )
                .addFilterAt(jwtAuthenticationFilter, SecurityWebFiltersOrder.AUTHENTICATION)
//                .addFilterBefore(jwtExceptionHandlerFilter, SecurityWebFiltersOrder.AUTHENTICATION) -> 비동기 동작으로 예외 핸들링 어려움
                .exceptionHandling(exceptionHandlingSpec ->
                        exceptionHandlingSpec.authenticationEntryPoint(authenticationExceptionEntryPoint)
                )
                .cors(corsSpec ->
                        corsSpec.configurationSource(corsConfig())
                )
                .csrf(csrfSpec ->
                        csrfSpec.disable() // csrf 비활성화
                )
                .httpBasic(httpBasicSpec ->
                        httpBasicSpec.disable() // HTTP 기본 인증 비활성화
                )
                .formLogin(formLoginSpec ->
                        formLoginSpec.disable() // form 로그인 비활성화
                )
                .build();
    }

    @Bean
    public CorsConfigurationSource corsConfig() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowCredentials(true); // 브라우저 자격 증명 요청 허용 (쿠키)
        configuration.setAllowedOriginPatterns(List.of("*")); // 허용 도메인
        configuration.setAllowedMethods(
                Arrays.asList("HEAD", "GET", "POST", "PUT", "PATCH", "DELETE")); // 허용 HTTP 메서드
        configuration.setAllowedHeaders(List.of("*")); // 허용 HTTP 헤더

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration); // 특정 경로에 대해 cors config 적용
        return source;
    }
}
