package com.zigix.todoitserver.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.zigix.todoitserver.domain.model.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

@Component
public class JwtTokenUtil {
    private final Algorithm algorithm = Algorithm.HMAC512("secret");
    private final JWTVerifier verifier = JWT.require(algorithm).build();

    public String generateAccessToken(User user) {
        return JWT.create()
                .withSubject(user.getUsername())
                .withIssuedAt(Date.from(Instant.now()))
                .withExpiresAt(Date.from(Instant.now().plus(1, ChronoUnit.MINUTES)))
                .withClaim("roles", user.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList())
                .withClaim("TokenType", "access token")
                .sign(algorithm);
    }

    public String generateRefreshToken(User user) {
        return JWT.create()
                .withSubject(user.getUsername())
                .withIssuedAt(Date.from(Instant.now()))
                .withExpiresAt(Date.from(Instant.now().plus(10, ChronoUnit.MINUTES)))
                .withClaim("TokenType", "refresh token")
                .sign(algorithm);
    }

    public boolean validateJwt(String token) {
        verifier.verify(token);
        return true;
    }

    public String getUsername(String accessToken) {
        DecodedJWT decodedJWT = verifier.verify(accessToken);
        return decodedJWT.getSubject();
    }

    public String[] getRoles(String accessToken) {
        DecodedJWT decodedJWT = verifier.verify(accessToken);
        return decodedJWT.getClaim("roles").asArray(String.class);
    }
}