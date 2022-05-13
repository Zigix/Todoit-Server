package com.zigix.todoitserver.service;

import com.zigix.todoitserver.domain.exception.VerificationTokenNotFoundException;
import com.zigix.todoitserver.domain.model.User;
import com.zigix.todoitserver.domain.model.VerificationToken;
import com.zigix.todoitserver.repository.VerificationTokenRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.catchThrowable;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;
import static org.mockito.Mockito.times;

@ExtendWith(MockitoExtension.class)
class VerificationTokenServiceImplTest {

    @Mock
    private VerificationTokenRepository mockVerificationTokenRepository;

    @InjectMocks
    private VerificationTokenServiceImpl systemUnderTest;

    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    @Test
    void should_generateVerificationTokenForGivenUser() {
        // given
        LocalDateTime now = LocalDateTime.now();
        User user = User.builder()
                .id(1L)
                .email("john@gmail.com")
                .username("john")
                .password(new BCryptPasswordEncoder().encode("qwertyuiop"))
                .createdDate(now)
                .lastModifiedDate(now)
                .enabled(false)
                .build();

        // when
        String generatedToken = systemUnderTest.generateToken(user);

        // then
        ArgumentCaptor<VerificationToken> tokenArgumentCaptor =
                ArgumentCaptor.forClass(VerificationToken.class);

        then(mockVerificationTokenRepository)
                .should(times(1))
                .save(tokenArgumentCaptor.capture());
        VerificationToken capturedToken = tokenArgumentCaptor.getValue();

        assertThat(capturedToken.getId()).isNull();
        assertThat(capturedToken.getToken()).isEqualTo(generatedToken);
        assertThat(capturedToken.getCreatedDate()).isNull();
        assertThat(capturedToken.getOwner()).isEqualTo(user);
    }

    @Test
    void should_throwVerificationTokenNotFoundException_when_noVerificationTokenWithPassedTokenValue() {
        // given
        String testTokenValue = UUID.randomUUID().toString();

        given(mockVerificationTokenRepository.findByToken(anyString()))
                .willReturn(Optional.empty());

        // when
        Throwable thrown = catchThrowable(() -> systemUnderTest.getByTokenValue(testTokenValue));

        // then
        then(mockVerificationTokenRepository)
                .should(times(1))
                .findByToken(testTokenValue);

        assertThat(thrown)
                .isInstanceOf(VerificationTokenNotFoundException.class)
                .hasMessageContaining("not found");
    }

    @Test
    void should_returnVerificationToken_when_passedTokenValueIsCorrect() {
        // given
        User testUser = new User(
                1L,
                "john@example.com",
                "john",
                passwordEncoder.encode("12345678"),
                LocalDateTime.parse("2007-12-03T10:15:30"),
                LocalDateTime.parse("2007-12-03T10:15:30"),
                false
        );
        String testTokenValue = UUID.randomUUID().toString();
        VerificationToken testVerificationToken = new VerificationToken(
                1L,
                testTokenValue,
                LocalDateTime.now(),
                testUser
        );

        given(mockVerificationTokenRepository.findByToken(anyString()))
                .willReturn(Optional.of(testVerificationToken));

        // when
        VerificationToken expected = systemUnderTest.getByTokenValue(testTokenValue);

        // then
        then(mockVerificationTokenRepository)
                .should(times(1))
                .findByToken(testTokenValue);

        assertThat(expected).isEqualTo(testVerificationToken);
    }
}