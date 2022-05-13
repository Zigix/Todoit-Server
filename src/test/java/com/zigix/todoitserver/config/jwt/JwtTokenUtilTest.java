package com.zigix.todoitserver.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.zigix.todoitserver.domain.model.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.catchThrowable;

@ExtendWith(SpringExtension.class)
class JwtTokenUtilTest {

    private JwtTokenUtil systemUnderTest;

    private final Algorithm algorithm = Algorithm.HMAC512("secret");
    private final JWTVerifier verifier = JWT.require(algorithm).build();

    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    @BeforeEach
    void setUp() {
        systemUnderTest = new JwtTokenUtil();
    }

    @Test
    void should_generateAccessTokenForGivenUser() {
        // given
        User testUser = getTestUser();

        // when
        String generatedToken = systemUnderTest.generateAccessToken(testUser);

        // then
        DecodedJWT decodedJWT = verifier.verify(generatedToken);

        assertThat(decodedJWT.getAlgorithm()).isEqualTo(algorithm.getName());
        assertThat(decodedJWT.getSubject()).isEqualTo(testUser.getUsername());
        assertThat(decodedJWT.getClaim(JwtTokenUtil.CLAIM_NAME_FOR_ROLES).asList(String.class))
                .isEqualTo(testUser.getAuthorities().stream().map(Object::toString).toList());
        assertThat(decodedJWT.getClaim(JwtTokenUtil.CLAIM_NAME_FOR_TOKEN_TYPE).asString()).isEqualTo("access token");

        Date issuedAt = decodedJWT.getIssuedAt();
        Date expiresAt = decodedJWT.getExpiresAt();
        long dateDiffInMillis = Math.abs(expiresAt.getTime() - issuedAt.getTime());
        long dateDiffInMinutes = TimeUnit.MINUTES.convert(Duration.of(dateDiffInMillis, ChronoUnit.MILLIS));
        assertThat(dateDiffInMinutes).isEqualTo(JwtTokenUtil.ACCESS_TOKEN_EXPIRATION_TIME_DURATION);
    }

    @Test
    void should_generateRefreshTokenForGivenUser() {
        // given
        User testUser = getTestUser();

        // when
        String generatedToken = systemUnderTest.generateRefreshToken(testUser);

        // then
        DecodedJWT decodedJWT = verifier.verify(generatedToken);

        assertThat(decodedJWT.getAlgorithm()).isEqualTo(algorithm.getName());
        assertThat(decodedJWT.getSubject()).isEqualTo(testUser.getUsername());
        assertThat(decodedJWT.getClaim(JwtTokenUtil.CLAIM_NAME_FOR_TOKEN_TYPE).asString()).isEqualTo("refresh token");

        Date issuedAt = decodedJWT.getIssuedAt();
        Date expiresAt = decodedJWT.getExpiresAt();
        long dateDiffInMillis = Math.abs(expiresAt.getTime() - issuedAt.getTime());
        long dateDiffInMinutes = TimeUnit.MINUTES.convert(Duration.of(dateDiffInMillis, ChronoUnit.MILLIS));
        assertThat(dateDiffInMinutes).isEqualTo(JwtTokenUtil.REFRESH_TOKEN_EXPIRATION_TIME_DURATION);
    }

    @Test
    void should_validateJwtToken() {
        // given
        String testToken = JWT.create()
                .withSubject("john")
                .withIssuedAt(Date.from(Instant.now()))
                .withExpiresAt(Date.from(Instant.now().plus(10, ChronoUnit.MINUTES)))
                .withClaim("roles", List.of("USER"))
                .withClaim("tt", "access token")
                .sign(algorithm);

        // when
        Throwable thrown = catchThrowable(() -> systemUnderTest.validateJwt(testToken));

        // then
        assertThat(thrown).isNull();
    }

    @Test
    void should_throwJWTVerificationException_when_passedJwtTokenIsNotValid() {
        // given
        String testInvalidToken = "this.is.invalidJWT.token";

        // when
        Throwable thrown = catchThrowable(() -> systemUnderTest.validateJwt(testInvalidToken));

        // then
        assertThat(thrown)
                .isInstanceOf(JWTVerificationException.class);
    }

    @Test
    void should_returnUsernameFromGivenJwtToken() {
        // given
        String testToken = JWT.create()
                .withSubject("john")
                .withIssuedAt(Date.from(Instant.now()))
                .withExpiresAt(Date.from(Instant.now().plus(10, ChronoUnit.MINUTES)))
                .withClaim("roles", List.of("USER"))
                .withClaim("tt", "access token")
                .sign(algorithm);

        // when
        String expected = systemUnderTest.getUsername(testToken);

        // then
        assertThat(expected).isEqualTo("john");
    }

    @Test
    void should_returnTokenTypeFromGivenJwtToken() {
        // given
        String testToken = JWT.create()
                .withSubject("john")
                .withIssuedAt(Date.from(Instant.now()))
                .withExpiresAt(Date.from(Instant.now().plus(10, ChronoUnit.MINUTES)))
                .withClaim("roles", List.of("USER"))
                .withClaim("tt", "access token")
                .sign(algorithm);

        // when
        String expected = systemUnderTest.getTokenType(testToken);

        // then
        assertThat(expected).isEqualTo("access token");
    }

    private User getTestUser() {
        LocalDateTime now = LocalDateTime.now();
        return new User(
                1L,
                "john@example.com",
                "john",
                passwordEncoder.encode("12345678"),
                now,
                now,
                true
        );
    }
}