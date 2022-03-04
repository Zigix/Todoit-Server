package com.zigix.todoitserver.service;

import com.zigix.todoitserver.domain.dto.RegisterUserRequest;
import com.zigix.todoitserver.domain.exception.EmailExistsException;
import com.zigix.todoitserver.domain.exception.PasswordsDoesNotMatchException;
import com.zigix.todoitserver.domain.exception.UsernameExistsException;
import com.zigix.todoitserver.domain.model.User;
import com.zigix.todoitserver.repository.UserRepository;
import com.zigix.todoitserver.service.mail.MailContent;
import com.zigix.todoitserver.service.mail.MailMessageBuilder;
import com.zigix.todoitserver.service.mail.MailService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.junit4.SpringRunner;

import javax.validation.constraints.Email;

import java.util.UUID;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.*;

@ExtendWith(SpringExtension.class)
class AuthServiceImplTest {

    PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    @Test
    @Disabled
    void shouldSignUpNewUser() {
    }

    @Test
    @DisplayName("Should throw PasswordsDoesNotMatchException when trying to sign up new user")
    void shouldThrowPasswordsDoesNotMatchException() {
        // given
        RegisterUserRequest request = new RegisterUserRequest(
                "john@gmail.com",
                "john",
                "qwertyuiop",
                "12345678"
        );
        AuthService underTest = new AuthServiceImpl(null, null, null, null, null);

        // when
        // then
        assertThatThrownBy(() -> underTest.signUp(request))
                .isInstanceOf(PasswordsDoesNotMatchException.class)
                .hasMessageContaining("Passwords doesn't match");
    }

    @Test
    @DisplayName("Should throw UsernameExistsException when trying to sign up new user")
    void shouldThrowUsernameExistsException() {
        // given
        RegisterUserRequest request = new RegisterUserRequest(
                "john@gmail.com",
                "john",
                "qwertyuiop",
                "qwertyuiop"
        );
        UserRepository mockUserRepository = mock(UserRepository.class);
        given(mockUserRepository.existsByUsername(anyString()))
                .willReturn(true);
        AuthService underTest = new AuthServiceImpl(mockUserRepository, null, null, null, null);
        // when
        // then
        assertThatThrownBy(() -> underTest.signUp(request))
                .isInstanceOf(UsernameExistsException.class)
                .hasMessageContaining(String.format("User with name %s already exists", request.getUsername()));
    }

    @Test
    @DisplayName("Should throw EmailExistsException when trying to sign up new user")
    void shouldThrowEmailExistsException() {
        // given
        RegisterUserRequest request = new RegisterUserRequest(
                "john@gmail.com",
                "john",
                "qwertyuiop",
                "qwertyuiop"
        );
        UserRepository mockUserRepository = mock(UserRepository.class);
        given(mockUserRepository.existsByUsername(anyString()))
                .willReturn(false);
        given(mockUserRepository.existsByEmail(anyString()))
                .willReturn(true);
        AuthService underTest = new AuthServiceImpl(mockUserRepository, null, null, null, null);
        // when
        // then
        assertThatThrownBy(() -> underTest.signUp(request))
                .isInstanceOf(EmailExistsException.class)
                .hasMessageContaining(String.format("User with email %s already exists", request.getEmail()));
    }

    @Test
    void shouldSignUpNewUserAndSendConfirmationEmail() {
        // given
        RegisterUserRequest request = new RegisterUserRequest(
                "john@gmail.com",
                "john",
                "qwertyuiop",
                "qwertyuiop"
        );
        UserRepository mockUserRepository = mock(UserRepository.class);
        MailService mockMailService = mock(MailService.class);
        MailMessageBuilder mockMailMessageBuilder = mock(MailMessageBuilder.class);
        VerificationTokenService mockVerificationTokenService = mock(VerificationTokenService.class);
        String generatedTokenTest = UUID.randomUUID().toString();

        AuthService underTest = new AuthServiceImpl(
                mockUserRepository,
                passwordEncoder,
                mockMailService,
                mockMailMessageBuilder,
                mockVerificationTokenService
        );

        given(mockVerificationTokenService.generateToken(any()))
                .willReturn(generatedTokenTest);

        // when
        underTest.signUp(request);

        // then
        verify(mockUserRepository).existsByUsername(request.getUsername());
        verify(mockUserRepository).existsByEmail(request.getEmail());

        ArgumentCaptor<User> userArgumentCaptor = ArgumentCaptor.forClass(User.class);
        ArgumentCaptor<MailContent> mailContentArgumentCaptor = ArgumentCaptor.forClass(MailContent.class);

        verify(mockUserRepository).save(userArgumentCaptor.capture());

        User capturedUser = userArgumentCaptor.getValue();

        assertThat(capturedUser.getId()).isNull();
        assertThat(capturedUser.getEmail()).isEqualTo(request.getEmail());
        assertThat(capturedUser.getUsername()).isEqualTo(request.getUsername());
        assertThat(passwordEncoder.matches(request.getPassword(), capturedUser.getPassword())).isTrue();
        assertThat(capturedUser.getCreatedDate()).isNull();
        assertThat(capturedUser.getLastModifiedDate()).isNull();
        assertThat(capturedUser.isEnabled()).isFalse();

        verify(mockMailService).sendMail(mailContentArgumentCaptor.capture());

        MailContent capturedMailContent = mailContentArgumentCaptor.getValue();

        assertThat(capturedMailContent.getRecipient()).isEqualTo(capturedUser.getEmail());
        assertThat(capturedMailContent.getSubject()).isEqualTo("Confirm your account");
    }
}