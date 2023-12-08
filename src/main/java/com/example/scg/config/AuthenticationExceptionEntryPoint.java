package com.example.scg.config;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class AuthenticationExceptionEntryPoint implements ServerAuthenticationEntryPoint {

    // jwt 검증 실패하여 인증되지 않은 경우 처리
    @Override
    public Mono<Void> commence(ServerWebExchange exchange, AuthenticationException ex) {
        String jwtError = exchange.getAttribute("jwtError");

        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        String responseJson = "{\"resMsg\":\"" + jwtError + "\"}";
        return response.writeWith(Mono.just(response.bufferFactory().wrap(responseJson.getBytes())));
    }
}
