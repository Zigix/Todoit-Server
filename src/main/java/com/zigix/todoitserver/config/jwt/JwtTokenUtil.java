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
import java.time.temporal.TemporalUnit;
import java.util.Date;

@Component
public class JwtTokenUtil {
    public static final int ACCESS_TOKEN_EXPIRATION_TIME_DURATION = 10;
    public static final TemporalUnit ACCESS_TOKEN_EXPIRATION_TIME_UNIT = ChronoUnit.MINUTES;
    public static final String CLAIM_NAME_FOR_ROLES = "roles";
    public static final String CLAIM_NAME_FOR_TOKEN_TYPE = "tt";
    public static final String ACCESS_TOKEN_NAME = "access token";
    public static final String REFRESH_TOKEN_NAME = "refresh token";

    private final Algorithm algorithm = Algorithm.HMAC512("secret");
    private final JWTVerifier verifier = JWT.require(algorithm).build();

    public String generateAccessToken(User user) {
        return JWT.create()
                .withSubject(user.getUsername())
                .withIssuedAt(Date.from(Instant.now()))
                .withExpiresAt(Date.from(Instant.now().plus(
                        ACCESS_TOKEN_EXPIRATION_TIME_DURATION,
                        ACCESS_TOKEN_EXPIRATION_TIME_UNIT)))
                .withClaim(CLAIM_NAME_FOR_ROLES,
                        user.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList())
                .withClaim(CLAIM_NAME_FOR_TOKEN_TYPE, ACCESS_TOKEN_NAME)
                .sign(algorithm);
    }

    public String generateRefreshToken(User user) {
        return JWT.create()
                .withSubject(user.getUsername())
                .withIssuedAt(Date.from(Instant.now()))
                .withExpiresAt(Date.from(Instant.now().plus(10, ChronoUnit.MINUTES)))
                .withClaim(CLAIM_NAME_FOR_TOKEN_TYPE, REFRESH_TOKEN_NAME)
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
        return decodedJWT.getClaim(CLAIM_NAME_FOR_ROLES).asArray(String.class);
    }

    public String getTokenType(String token) {
        DecodedJWT decodedJWT = verifier.verify(token);
        return decodedJWT.getClaim(CLAIM_NAME_FOR_TOKEN_TYPE).asString();
    }
}
