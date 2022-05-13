package com.zigix.todoitserver.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.zigix.todoitserver.config.jwt.JwtTokenUtil;
import com.zigix.todoitserver.domain.dto.AccessTokensResponse;
import com.zigix.todoitserver.domain.dto.RegisterUserRequest;
import com.zigix.todoitserver.domain.exception.*;
import com.zigix.todoitserver.domain.mapper.UserMapper;
import com.zigix.todoitserver.domain.model.User;
import com.zigix.todoitserver.domain.model.VerificationToken;
import com.zigix.todoitserver.repository.UserRepository;
import com.zigix.todoitserver.service.mail.MailContent;
import com.zigix.todoitserver.service.mail.MailMessageBuilder;
import com.zigix.todoitserver.service.mail.MailService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import javax.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static com.zigix.todoitserver.config.jwt.JwtTokenUtil.CLAIM_NAME_FOR_ROLES;
import static com.zigix.todoitserver.config.jwt.JwtTokenUtil.CLAIM_NAME_FOR_TOKEN_TYPE;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.catchThrowable;
import static org.mockito.BDDMockito.*;

@ExtendWith(SpringExtension.class)
class AuthServiceImplTest {

    @Mock
    private UserRepository mockUserRepository;
    @Mock
    private MailService mockMailService;
    @Mock
    private MailMessageBuilder mockMailMessageBuilder;
    @Mock
    private VerificationTokenService mockVerificationTokenService;
    @Mock
    private JwtTokenUtil mockJwtTokenUtil;
    @Mock
    private UserMapper mockUserMapper;

    @InjectMocks
    private AuthServiceImpl systemUnderTest;

    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    @Test
    void should_throwPasswordsDoesNotMatchException_when_signUpNewUserWithDifferentPasswords() {
        // given
        RegisterUserRequest request = new RegisterUserRequest(
                "john@gmail.com",
                "john",
                "qwertyuiop",
                "12345678"
        );

        // when
        Throwable thrown = catchThrowable(() -> systemUnderTest.signUp(request));

        // then
        assertThat(thrown)
                .isInstanceOf(PasswordsDoesNotMatchException.class)
                .hasMessageContaining("Passwords doesn't match");
    }

    @Test
    void should_throwUsernameExistsException_when_signUpNewUserWithUsernameThatAlreadyExists() {
        // given
        RegisterUserRequest request = new RegisterUserRequest(
                "john@gmail.com",
                "john",
                "qwertyuiop",
                "qwertyuiop"
        );

        given(mockUserRepository.existsByUsername(anyString()))
                .willReturn(true);

        // when
        Throwable thrown = catchThrowable(() -> systemUnderTest.signUp(request));

        // then
        assertThat(thrown)
                .isInstanceOf(UsernameExistsException.class)
                .hasMessageContaining(String.format("User with name %s already exists", request.getUsername()));
    }

    @Test
    void should_throwEmailExistsException_when_signUpNewUserWithEmailThatAlreadyExists() {
        // given
        RegisterUserRequest request = new RegisterUserRequest(
                "john@gmail.com",
                "john",
                "qwertyuiop",
                "qwertyuiop"
        );

        given(mockUserRepository.existsByUsername(anyString()))
                .willReturn(false);
        given(mockUserRepository.existsByEmail(anyString()))
                .willReturn(true);

        // when
        Throwable thrown = catchThrowable(() -> systemUnderTest.signUp(request));

        // then
        assertThat(thrown)
                .isInstanceOf(EmailExistsException.class)
                .hasMessageContaining(String.format("User with email %s already exists", request.getEmail()));
    }

    @Test
    void should_signUpNewUserAndSendConfirmationEmail_when_newUserDataIsCorrect() {
        // given
        String testToken = UUID.randomUUID().toString();
        RegisterUserRequest testRequest = new RegisterUserRequest(
                "john@gmail.com",
                "john",
                "qwertyuiop",
                "qwertyuiop"
        );
        User testUser = new User(
                null,
                "john@gmail.com",
                "john",
                passwordEncoder.encode("qwertyuiop"),
                null,
                null,
                false
        );

        given(mockVerificationTokenService.generateToken(any()))
                .willReturn(testToken);
        given(mockUserMapper.mapToUser(any(RegisterUserRequest.class)))
                .willReturn(testUser);
        given(mockMailMessageBuilder.getRegistrationMailContent(anyString(), anyString()))
                .willReturn("Registration mail content text");

        // when
        systemUnderTest.signUp(testRequest);

        // then
        then(mockUserRepository)
                .should(times(1))
                .existsByUsername(testRequest.getUsername());
        then(mockUserRepository)
                .should(times(1))
                .existsByEmail(testRequest.getEmail());
        then(mockUserMapper)
                .should(times(1))
                .mapToUser(testRequest);

        ArgumentCaptor<MailContent> mailContentArgumentCaptor = ArgumentCaptor.forClass(MailContent.class);

        then(mockUserRepository)
                .should(times(1))
                .save(testUser);

        then(mockVerificationTokenService)
                .should(times(1))
                .generateToken(testUser);

        then(mockMailService)
                .should(times(1))
                .sendMail(mailContentArgumentCaptor.capture());

        MailContent capturedMailContent = mailContentArgumentCaptor.getValue();

        assertThat(capturedMailContent.getRecipient()).isEqualTo(testUser.getEmail());
        assertThat(capturedMailContent.getSubject()).isEqualTo(AuthServiceImpl.CONFIRMATION_EMAIL_SUBJECT);
        assertThat(capturedMailContent.getText()).isEqualTo("Registration mail content text");

        then(mockMailMessageBuilder)
                .should(times(1))
                .getRegistrationMailContent(
                        testUser.getUsername(),
                        AuthServiceImpl.CONFIRMATION_TOKEN_LINK_PREFIX + testToken
                );
    }

    @Test
    void should_throwUserVerifiedException_when_verifyUserAccountThatIsAlreadyVerified() {
        // given
        String token = UUID.randomUUID().toString();
        User tokenOwner = getTestUserWithEnabled(true);
        VerificationToken testVerificationToken = new VerificationToken(
                1L,
                token,
                LocalDateTime.parse("2007-12-03T10:15:30"),
                tokenOwner
        );

        given(mockVerificationTokenService.getByTokenValue(anyString()))
                .willReturn(testVerificationToken);

        // when
        Throwable thrown = catchThrowable(() -> systemUnderTest.verifyUserByToken(token));

        // then
        assertThat(thrown)
                .isInstanceOf(UserVerifiedException.class)
                .hasMessageContaining("User already verified");
    }

    @Test
    void should_verifyUserAccount_when_userVerificationTokenIsCorrect() {
        // given
        String testToken = UUID.randomUUID().toString();
        User tokenOwner = getTestUserWithEnabled(false);
        VerificationToken testVerificationToken = new VerificationToken(
                1L,
                testToken,
                LocalDateTime.parse("2007-12-03T10:15:30"),
                tokenOwner
        );

        given(mockVerificationTokenService.getByTokenValue(anyString()))
                .willReturn(testVerificationToken);

        // when
        systemUnderTest.verifyUserByToken(testToken);

        // then
        then(mockVerificationTokenService)
                .should(times(1))
                .getByTokenValue(testToken);

        assertThat(tokenOwner.isEnabled()).isTrue();
    }

    @Test
    void should_returnCurrentlyLoggedUser() {
        // given
        User testUser = getTestUserWithEnabled(true);
        Authentication mockAuthentication = mock(Authentication.class);
        SecurityContext mockSecurityContext = mock(SecurityContext.class);

        given(mockAuthentication.getPrincipal())
                .willReturn(testUser);
        given(mockSecurityContext.getAuthentication())
                .willReturn(mockAuthentication);

        SecurityContextHolder.setContext(mockSecurityContext);

        // when
        User expected = systemUnderTest.getLoggedUser();

        // then
        assertThat(expected).isEqualTo(testUser);
    }

    @Test
    void should_throwJWTVerificationException_when_passedJWTTokenIsIncorrect() {
        // given
        HttpServletRequest mockHttpServletRequest = mock(HttpServletRequest.class);

        given(mockHttpServletRequest.getHeader(anyString()))
                .willReturn("ThisIsNotValidJwtToken");
        doThrow(JWTVerificationException.class)
                .when(mockJwtTokenUtil)
                .validateJwt(anyString());

        // when
        Throwable thrown = catchThrowable(() -> systemUnderTest.refreshToken(mockHttpServletRequest));

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
        verifyNoInteractions(mockUserRepository);
    }

    @Test
    void should_throwInvalidTokenTypeException_when_passedJwtTokenIsNotRefreshTokenType() {
        // given
        String testRefreshToken = getTestJwtToken(
                "john",
                Date.from(Instant.now()),
                Date.from(Instant.now().plus(1000, ChronoUnit.MINUTES)),
                "refresh token");

        HttpServletRequest mockHttpServletRequest = mock(HttpServletRequest.class);

        given(mockHttpServletRequest.getHeader(anyString()))
                .willReturn("Bearer " + testRefreshToken);
        given(mockJwtTokenUtil.getTokenType(anyString()))
                .willReturn("StringWithBadTokenType");

        // when
        Throwable throwable = catchThrowable(() -> systemUnderTest.refreshToken(mockHttpServletRequest));

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

        assertThat(throwable)
                .isInstanceOf(InvalidTokenTypeException.class)
                .hasMessageContaining("Invalid token type");

        verifyNoMoreInteractions(mockJwtTokenUtil);
        verifyNoInteractions(mockUserRepository);
    }

    @Test
    void should_throwUsernameNotFoundException_when_noUserWithUsernameExtractedFromJwtToken() {
        String testRefreshToken = getTestJwtToken(
                "john",
                Date.from(Instant.now()),
                Date.from(Instant.now().plus(1000, ChronoUnit.MINUTES)),
                "refresh token");

        HttpServletRequest mockHttpServletRequest = mock(HttpServletRequest.class);

        given(mockHttpServletRequest.getHeader(anyString()))
                .willReturn("Bearer " + testRefreshToken);
        given(mockJwtTokenUtil.getTokenType(anyString()))
                .willReturn("refresh token");
        given(mockJwtTokenUtil.getUsername(anyString()))
                .willReturn("john");
        given(mockUserRepository.findByUsername(anyString()))
                .willReturn(Optional.empty());

        // when
        Throwable thrown = catchThrowable(() -> systemUnderTest.refreshToken(mockHttpServletRequest));

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
        then(mockJwtTokenUtil)
                .should(times(1))
                .getUsername(testRefreshToken);
        then(mockUserRepository)
                .should(times(1))
                .findByUsername("john");

        assertThat(thrown)
                .isInstanceOf(UsernameNotFoundException.class)
                .hasMessageContaining("not found");

        verifyNoMoreInteractions(mockJwtTokenUtil);
    }

    @Test
    void should_returnAccessTokenAndRefreshToken_when_passedRefreshTokenIsCorrect() {
        // given
        User testUser = getTestUserWithEnabled(true);

        String testRefreshToken = getTestJwtToken(
                testUser.getUsername(),
                Date.from(Instant.now()),
                Date.from(Instant.now().plus(1000, ChronoUnit.MINUTES)),
                "refresh token");
        String testAccessToken = getTestJwtToken(
                testUser.getUsername(),
                Date.from(Instant.now()),
                Date.from(Instant.now().plus(1, ChronoUnit.MINUTES)),
                "access token");
        HttpServletRequest mockHttpServletRequest = mock(HttpServletRequest.class);

        given(mockHttpServletRequest.getHeader(anyString()))
                .willReturn("Bearer " + testRefreshToken);
        given(mockJwtTokenUtil.getTokenType(anyString()))
                .willReturn("refresh token");
        given(mockJwtTokenUtil.getUsername(anyString()))
                .willReturn(testUser.getUsername());
        given(mockUserRepository.findByUsername(anyString()))
                .willReturn(Optional.of(testUser));
        given(mockJwtTokenUtil.generateAccessToken(any(User.class)))
                .willReturn(testAccessToken);

        // when
        AccessTokensResponse expected = systemUnderTest.refreshToken(mockHttpServletRequest);

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
        then(mockJwtTokenUtil)
                .should(times(1))
                .getUsername(testRefreshToken);
        then(mockUserRepository)
                .should(times(1))
                .findByUsername(testUser.getUsername());
        then(mockJwtTokenUtil)
                .should(times(1))
                .generateAccessToken(testUser);

        assertThat(expected.getAccessToken()).isEqualTo(testAccessToken);
        assertThat(expected.getRefreshToken()).isEqualTo(testRefreshToken);
    }

    private User getTestUserWithEnabled(boolean enabled) {
        return new User(
                1L,
                "john@example.com",
                "john",
                passwordEncoder.encode("12345678"),
                LocalDateTime.parse("2007-12-03T10:15:30"),
                LocalDateTime.parse("2007-12-03T10:15:30"),
                enabled
        );
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


