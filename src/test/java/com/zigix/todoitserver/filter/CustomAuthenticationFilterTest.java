package com.zigix.todoitserver.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zigix.todoitserver.config.jwt.JwtTokenUtil;
import com.zigix.todoitserver.domain.dto.AuthenticationResponse;
import com.zigix.todoitserver.domain.dto.LoginRequest;
import com.zigix.todoitserver.domain.dto.UserView;
import com.zigix.todoitserver.domain.mapper.UserMapper;
import com.zigix.todoitserver.domain.model.User;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.ConstraintViolation;
import javax.validation.ConstraintViolationException;
import javax.validation.Path;
import javax.validation.Validator;
import javax.validation.metadata.ConstraintDescriptor;
import java.io.IOException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.*;

import static com.zigix.todoitserver.config.jwt.JwtTokenUtil.CLAIM_NAME_FOR_ROLES;
import static com.zigix.todoitserver.config.jwt.JwtTokenUtil.CLAIM_NAME_FOR_TOKEN_TYPE;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.catchThrowable;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CustomAuthenticationFilterTest {

    @Mock
    private JwtTokenUtil mockJwtTokenUtil;
    @Mock
    private UserMapper mockUserMapper;
    @Mock
    private AuthenticationManager mockAuthenticationManager;
    @Mock
    private ObjectMapper mockObjectMapper;
    @Mock
    private Validator mockValidator;

    @InjectMocks
    private CustomAuthenticationFilter systemUnderTest;

    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    @Test
    void should_attemptAuthentication_success() throws IOException {
        // given
        LoginRequest testLoginRequest = new LoginRequest("john", "12345678");
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                testLoginRequest.getUsername(),
                testLoginRequest.getPassword()
        );

        HttpServletRequest mockHttpServletRequest = mock(HttpServletRequest.class);
        HttpServletResponse mockHttpServletResponse = mock(HttpServletResponse.class);

        given(mockObjectMapper.readValue(mockHttpServletRequest.getInputStream(), LoginRequest.class))
                .willReturn(testLoginRequest);
        given(mockValidator.validate(any(LoginRequest.class)))
                .willReturn(Collections.emptySet());

        ArgumentCaptor<UsernamePasswordAuthenticationToken> captureAuthToken =
                ArgumentCaptor.forClass(UsernamePasswordAuthenticationToken.class);

        // when
        systemUnderTest.attemptAuthentication(mockHttpServletRequest, mockHttpServletResponse);

        // then
        then(mockObjectMapper)
                .should(times(1))
                .readValue(mockHttpServletRequest.getInputStream(), LoginRequest.class);
        then(mockValidator)
                .should(times(1))
                .validate(testLoginRequest);
        then(mockAuthenticationManager)
                .should(times(1))
                .authenticate(captureAuthToken.capture());

        assertThat(captureAuthToken.getValue()).isEqualTo(authToken);
    }

    @Test
    void should_throwIOException_when_readingStreamUsingObjectMapper() throws IOException {
        // given
        HttpServletRequest mockHttpServletRequest = mock(HttpServletRequest.class);
        HttpServletResponse mockHttpServletResponse = mock(HttpServletResponse.class);
        ServletInputStream mockServletInputStream = mock(ServletInputStream.class);

        given(mockHttpServletRequest.getInputStream())
                .willReturn(mockServletInputStream);
        given(mockObjectMapper.readValue(mockServletInputStream, LoginRequest.class))
                .willThrow(IOException.class);

        // when
        systemUnderTest.attemptAuthentication(mockHttpServletRequest, mockHttpServletResponse);

        // then
        then(mockObjectMapper)
                .should(times(1))
                .readValue(mockHttpServletRequest.getInputStream(), LoginRequest.class);

        then(mockAuthenticationManager)
                .should(times(1))
                .authenticate(null);
    }

    @Test
    void should_throwConstraintViolationException_when_loginRequestHasValidationErrors() throws IOException {
        // given
        LoginRequest testBadLoginRequest = new LoginRequest(
                null,
                "    "
        );
        Set<ConstraintViolation<LoginRequest>> testSetOfConstraints =
                getSetOfConstraints("message 1", "message 2");

        HttpServletRequest mockHttpServletRequest = mock(HttpServletRequest.class);
        HttpServletResponse mockHttpServletResponse = mock(HttpServletResponse.class);

        given(mockObjectMapper.readValue(mockHttpServletRequest.getInputStream(), LoginRequest.class))
                .willReturn(testBadLoginRequest);
        given(mockValidator.validate(any(LoginRequest.class)))
                .willReturn(testSetOfConstraints);

        // when
        Throwable thrown = catchThrowable(() ->
                systemUnderTest.attemptAuthentication(mockHttpServletRequest, mockHttpServletResponse));

        // then
        then(mockObjectMapper)
                .should(times(1))
                .readValue(mockHttpServletRequest.getInputStream(), LoginRequest.class);
        then(mockValidator)
                .should(times(1))
                .validate(testBadLoginRequest);

        assertThat(thrown)
                .isInstanceOf(ConstraintViolationException.class);

        verifyNoInteractions(mockAuthenticationManager);
    }

    private Set<ConstraintViolation<LoginRequest>> getSetOfConstraints(String... messages) {
        Set<ConstraintViolation<LoginRequest>> constraintViolations = new HashSet<>();
        for (String message : messages) {
            constraintViolations.add(new ConstraintViolation<>() {
                @Override
                public String getMessage() {
                    return message;
                }

                @Override
                public String getMessageTemplate() {
                    return null;
                }

                @Override
                public LoginRequest getRootBean() {
                    return null;
                }

                @Override
                public Class<LoginRequest> getRootBeanClass() {
                    return null;
                }

                @Override
                public Object getLeafBean() {
                    return null;
                }

                @Override
                public Object[] getExecutableParameters() {
                    return new Object[0];
                }

                @Override
                public Object getExecutableReturnValue() {
                    return null;
                }

                @Override
                public Path getPropertyPath() {
                    return null;
                }

                @Override
                public Object getInvalidValue() {
                    return null;
                }

                @Override
                public ConstraintDescriptor<?> getConstraintDescriptor() {
                    return null;
                }

                @Override
                public <U> U unwrap(Class<U> type) {
                    return null;
                }
            });
        }
        return constraintViolations;
    }

    @Test
    void should_successfulAuthentication_success() throws ServletException, IOException {
        User testUser = new User(
                1L,
                "john@example.com",
                "john",
                passwordEncoder.encode("12345678"),
                LocalDateTime.parse("2007-12-03T10:15:30"),
                LocalDateTime.parse("2007-12-03T10:15:30"),
                true
        );
        UserView testUserView = new UserView(
                testUser.getId(),
                testUser.getEmail(),
                testUser.getUsername(),
                testUser.getCreatedDate(),
                testUser.getLastModifiedDate(),
                testUser.isEnabled()
        );
        String testAccessToken = getTestJwtToken(
                testUser.getUsername(),
                Date.from(Instant.now()),
                Date.from(Instant.now().plus(1, ChronoUnit.MINUTES)),
                "access token"
        );
        String testRefreshToken = getTestJwtToken(
                testUser.getUsername(),
                Date.from(Instant.now()),
                Date.from(Instant.now().plus(1000, ChronoUnit.MINUTES)),
                "refresh token"
        );
        HttpServletRequest mockHttpServletRequest = mock(HttpServletRequest.class);
        HttpServletResponse mockHttpServletResponse = mock(HttpServletResponse.class);
        FilterChain mockFilterChain = mock(FilterChain.class);
        Authentication mockAuthentication = mock(Authentication.class);
        ServletOutputStream mockServletOutputStream = mock(ServletOutputStream.class);

        given(mockAuthentication.getPrincipal())
                .willReturn(testUser);
        given(mockJwtTokenUtil.generateAccessToken(any(User.class)))
                .willReturn(testAccessToken);
        given(mockJwtTokenUtil.generateRefreshToken(any(User.class)))
                .willReturn(testRefreshToken);
        given(mockUserMapper.mapToUserView(any(User.class)))
                .willReturn(testUserView);
        given(mockHttpServletResponse.getOutputStream())
                .willReturn(mockServletOutputStream);

        ArgumentCaptor<AuthenticationResponse> authenticationResponseCapture =
                ArgumentCaptor.forClass(AuthenticationResponse.class);

        // when
        systemUnderTest.successfulAuthentication(
                mockHttpServletRequest,
                mockHttpServletResponse,
                mockFilterChain,
                mockAuthentication
        );

        // then
        then(mockAuthentication)
                .should(times(1))
                .getPrincipal();

        then(mockJwtTokenUtil)
                .should(times(1))
                .generateAccessToken(testUser);

        then(mockJwtTokenUtil)
                .should(times(1))
                .generateRefreshToken(testUser);

        then(mockHttpServletResponse)
                .should(times(1))
                .setContentType(MediaType.APPLICATION_JSON_VALUE);

        then(mockObjectMapper)
                .should(times(1))
                .writeValue(any(ServletOutputStream.class), authenticationResponseCapture.capture());
        AuthenticationResponse capturedAuthenticationResponse = authenticationResponseCapture.getValue();
        assertThat(capturedAuthenticationResponse.getUser()).isEqualTo(testUserView);
        assertThat(capturedAuthenticationResponse.getTokens().getAccessToken()).isEqualTo(testAccessToken);
        assertThat(capturedAuthenticationResponse.getTokens().getRefreshToken()).isEqualTo(testRefreshToken);
    }

    @Test
    void should_unsuccessfulAuthentication_success() throws IOException, ServletException {
        // given
        HttpServletRequest mockHttpServletRequest = mock(HttpServletRequest.class);
        HttpServletResponse mockHttpServletResponse = mock(HttpServletResponse.class);
        AuthenticationException mockAuthenticationException = mock(AuthenticationException.class);
        ServletOutputStream mockServletOutputStream = mock(ServletOutputStream.class);

        given(mockHttpServletResponse.getOutputStream())
                .willReturn(mockServletOutputStream);
        given(mockAuthenticationException.getMessage())
                .willReturn("Bad credentials");

        // when
        systemUnderTest.unsuccessfulAuthentication(
                mockHttpServletRequest,
                mockHttpServletResponse,
                mockAuthenticationException
        );

        // then
        then(mockObjectMapper)
                .should(times(1))
                .writeValue(mockHttpServletResponse.getOutputStream(), mockAuthenticationException.getMessage());
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