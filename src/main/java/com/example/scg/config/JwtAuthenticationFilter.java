package com.example.scg.config;


import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.stream.Collectors;

@RequiredArgsConstructor
@Component
public class JwtAuthenticationFilter implements WebFilter {
    private final JwtConfig jwtConfig;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {

        // 인증이 필요하지 않은 요청
        AntPathMatcher pathMatcher = new AntPathMatcher();
        if (pathMatcher.match("/auth/**", String.valueOf(exchange.getRequest().getPath()))) {
            return chain.filter(exchange);
        }

        String token = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        try {
            Claims claims = jwtConfig.validateToken(token); // 검증 후 claims 꺼내기
            List<SimpleGrantedAuthority> authorities = ((List<String>) claims.get("role")).stream()
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());
            // security 인증 처리
            Authentication authentication = new UsernamePasswordAuthenticationToken(claims.get("username"), null, authorities);
            return chain.filter(exchange).contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication));
        } catch (JwtConfig.TokenException e) {
            exchange.getAttributes().put("jwtError", e.getMessage()); // 실패 메시지 저장 > entry point에서 꺼내어 응답
            return chain.filter(exchange); // jwt 검증 실패 시 인증하지 않고 필터체인 진행
        }
    }

}
