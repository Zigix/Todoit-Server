package com.zigix.todoitserver.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.zigix.todoitserver.config.jwt.JwtTokenUtil;
import com.zigix.todoitserver.domain.model.User;
import com.zigix.todoitserver.service.UserService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EmptySource;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;

import static com.zigix.todoitserver.config.jwt.JwtTokenUtil.CLAIM_NAME_FOR_ROLES;
import static com.zigix.todoitserver.config.jwt.JwtTokenUtil.CLAIM_NAME_FOR_TOKEN_TYPE;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.catchThrowable;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;
import static org.mockito.Mockito.*;

@ExtendWith(SpringExtension.class)
class CustomAuthorizationFilterTest {

    @Mock
    private JwtTokenUtil mockJwtTokenUtil;
    @Mock
    private UserService mockUserService;
    @Mock
    private HttpServletRequest mockHttpServletRequest;
    @Mock
    private HttpServletResponse mockHttpServletResponse;
    @Mock
    private FilterChain mockFilterChain;

    @InjectMocks
    private CustomAuthorizationFilter underTest;

    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    @Test
    void should_throwJWTVerificationException_when_jwtTokenInAuthorizationHeaderIsIncorrect()
            throws ServletException, IOException {
        // given
        SecurityContext mockSecurityContext = mock(SecurityContext.class);

        SecurityContextHolder.setContext(mockSecurityContext);

        given(mockHttpServletRequest.getHeader(anyString()))
                .willReturn("BadAuthorizationHeader");
        doThrow(JWTVerificationException.class)
                .when(mockJwtTokenUtil)
                .validateJwt(anyString());

        // when
        Throwable thrown = catchThrowable(() ->
                underTest.doFilterInternal(mockHttpServletRequest, mockHttpServletResponse, mockFilterChain));

        // then
        then(mockHttpServletRequest)
                .should(times(1))
                .getHeader(HttpHeaders.AUTHORIZATION);

        then(mockJwtTokenUtil)
                .should(times(1))
                .validateJwt("");

        assertThat(thrown)
                .isInstanceOf(JWTVerificationException.class);

        verifyNoMoreInteractions(mockJwtTokenUtil);
        verifyNoInteractions(mockUserService, mockSecurityContext, mockFilterChain);
    }

    @Test
    void should_noAuthorizeRequest_when_passedAccessTokenHasInvalidTokenType() throws ServletException, IOException {
        String testRefreshToken = getTestJwtToken(
                "john",
                Date.from(Instant.now()),
                Date.from(Instant.now().plus(1, ChronoUnit.MINUTES)),
                "refresh token"
        );

        SecurityContext mockSecurityContext = mock(SecurityContext.class);

        SecurityContextHolder.setContext(mockSecurityContext);

        given(mockHttpServletRequest.getHeader(anyString()))
                .willReturn("Bearer " + testRefreshToken);
        given(mockJwtTokenUtil.getTokenType(anyString()))
                .willReturn(JwtTokenUtil.REFRESH_TOKEN_NAME);

        // when
        underTest.doFilterInternal(mockHttpServletRequest, mockHttpServletResponse, mockFilterChain);

        // then
        then(mockHttpServletRequest)
                .should(times(1))
                .getHeader(HttpHeaders.AUTHORIZATION);

        then(mockJwtTokenUtil)
                .should(times(1))
                .validateJwt(testRefreshToken);

        then(mockJwtTokenUtil)
                .should(times(1))
                .getTokenType(testRefreshToken);

        then(mockFilterChain)
                .should(times(1))
                .doFilter(mockHttpServletRequest, mockHttpServletResponse);

        verifyNoMoreInteractions(mockJwtTokenUtil);
        verifyNoInteractions(mockUserService, mockSecurityContext);
    }

    @Test
    void should_authorizeRequest_when_passedAccessTokenIsCorrect() throws ServletException, IOException {
        // given
        User testUser = new User(
                1L,
                "john@example.com",
                "john",
                passwordEncoder.encode("12345678"),
                LocalDateTime.parse("2007-12-03T10:15:30"),
                LocalDateTime.parse("2007-12-03T10:15:30"),
                true
        );
        String testAccessToken = getTestJwtToken(
                "john",
                Date.from(Instant.now()),
                Date.from(Instant.now().plus(1, ChronoUnit.MINUTES)),
                "access token"
        );

        HttpServletRequest mockHttpServletRequest = mock(HttpServletRequest.class);
        HttpServletResponse mockHttpServletResponse = mock(HttpServletResponse.class);
        FilterChain mockFilterChain = mock(FilterChain.class);
        SecurityContext mockSecurityContext = mock(SecurityContext.class);

        SecurityContextHolder.setContext(mockSecurityContext);

        given(mockHttpServletRequest.getHeader(anyString()))
                .willReturn("Bearer " + testAccessToken);
        given(mockJwtTokenUtil.getTokenType(anyString()))
                .willReturn(JwtTokenUtil.ACCESS_TOKEN_NAME);
        given(mockJwtTokenUtil.getUsername(anyString()))
                .willReturn(testUser.getUsername());
        given(mockUserService.loadUserByUsername(anyString()))
                .willReturn(testUser);


        ArgumentCaptor<UsernamePasswordAuthenticationToken> authenticationTokenCapture =
                ArgumentCaptor.forClass(UsernamePasswordAuthenticationToken.class);

        // when
        underTest.doFilterInternal(mockHttpServletRequest, mockHttpServletResponse, mockFilterChain);

        // then
        then(mockHttpServletRequest)
                .should(times(1))
                .getHeader(HttpHeaders.AUTHORIZATION);

        then(mockJwtTokenUtil)
                .should(times(1))
                .validateJwt(testAccessToken);

        then(mockJwtTokenUtil)
                .should(times(1))
                .getTokenType(testAccessToken);

        then(mockJwtTokenUtil)
                .should(times(1))
                .getUsername(testAccessToken);

        then(mockUserService)
                .should(times(1))
                .loadUserByUsername(testUser.getUsername());

        then(mockSecurityContext)
                .should(times(1))
                .setAuthentication(authenticationTokenCapture.capture());
        UsernamePasswordAuthenticationToken capturedAuthenticationToken = authenticationTokenCapture.getValue();
        assertThat(capturedAuthenticationToken.getPrincipal()).isEqualTo(testUser);
        assertThat(capturedAuthenticationToken.getCredentials()).isNull();
        assertThat(capturedAuthenticationToken.getAuthorities()).isEqualTo(testUser.getAuthorities());

        then(mockFilterChain)
                .should(times(1))
                .doFilter(mockHttpServletRequest, mockHttpServletResponse);
    }

    @ParameterizedTest
    @ValueSource(strings = {"/api/v1/auth", "/api/v1/auth/login", "/api/v1/auth/logout", "/api/v1/auth/verify/token"})
    void should_returnTrue_when_requestShouldNotBeFiltered(String testPath) throws ServletException {
        // given
        given(mockHttpServletRequest.getServletPath())
                .willReturn(testPath);

        // when
        boolean expected = underTest.shouldNotFilter(mockHttpServletRequest);

        // then
        then(mockHttpServletRequest)
                .should(times(1))
                .getServletPath();

        assertThat(expected).isTrue();
    }

    @ParameterizedTest
    @NullSource
    @EmptySource
    @ValueSource(strings = {"   ", "/api/v1", "/api/v1/users", "/api/v1/tasks"})
    void should_returnFalse_when_requestShouldBeFiltered(String testPath) throws ServletException {
        // given
        given(mockHttpServletRequest.getServletPath())
                .willReturn(testPath);

        // when
        boolean expected = underTest.shouldNotFilter(mockHttpServletRequest);

        // then
        then(mockHttpServletRequest)
                .should(times(1))
                .getServletPath();

        assertThat(expected).isFalse();
    }


    private String getTestJwtToken(String username, Date issuedAt, Date expiresAt, String tokenType) {
        JWTCreator.Builder jwtBuilder = JWT.create()
                .withSubject(username)
                .withIssuedAt(issuedAt)
                .withExpiresAt(expiresAt)
                .withClaim(CLAIM_NAME_FOR_TOKEN_TYPE, tokenType);

        if (tokenType.equals("access token")) {
            jwtBuilder.withClaim(CLAIM_NAME_FOR_ROLES, List.of("ROLE_USER"));

        }
        return jwtBuilder.sign(Algorithm.HMAC512("secret"));
    }
}