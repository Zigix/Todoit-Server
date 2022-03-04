package com.zigix.todoitserver.service;

import com.zigix.todoitserver.domain.model.User;
import com.zigix.todoitserver.domain.model.VerificationToken;
import com.zigix.todoitserver.repository.VerificationTokenRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.time.LocalDateTime;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class VerificationTokenServiceImplTest {

    @Mock
    VerificationTokenRepository verificationTokenRepository;

    VerificationTokenService underTest;

    @BeforeEach
    void setUp() {
        underTest = new VerificationTokenServiceImpl(verificationTokenRepository);
    }

    @Test
    void shouldGenerateTokenForGivenUser() {
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
        String generatedToken = underTest.generateToken(user);

        // then
        ArgumentCaptor<VerificationToken> tokenArgumentCaptor =
                ArgumentCaptor.forClass(VerificationToken.class);

        verify(verificationTokenRepository).save(tokenArgumentCaptor.capture());

        VerificationToken capturedToken = tokenArgumentCaptor.getValue();

        assertThat(capturedToken.getId()).isNull();
        assertThat(capturedToken.getToken()).isEqualTo(generatedToken);
        assertThat(capturedToken.getCreatedDate()).isNull();
        assertThat(capturedToken.getOwner()).isEqualTo(user);
    }
}