package com.zigix.todoitserver.service;

import com.zigix.todoitserver.domain.dto.RegisterUserRequest;
import com.zigix.todoitserver.domain.exception.EmailExistsException;
import com.zigix.todoitserver.domain.exception.PasswordsDoesNotMatchException;
import com.zigix.todoitserver.domain.exception.UsernameExistsException;
import com.zigix.todoitserver.domain.model.User;
import com.zigix.todoitserver.domain.model.VerificationToken;
import com.zigix.todoitserver.repository.UserRepository;
import com.zigix.todoitserver.repository.VerificationTokenRepository;
import com.zigix.todoitserver.service.mail.MailContent;
import com.zigix.todoitserver.service.mail.MailMessageBuilder;
import com.zigix.todoitserver.service.mail.MailService;
import com.zigix.todoitserver.util.Constants;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.annotation.Validated;

import javax.validation.Valid;

import static com.zigix.todoitserver.util.Constants.CONFIRMATION_EMAIL_SUBJECT;
import static com.zigix.todoitserver.util.Constants.CONFIRMATION_TOKEN_LINK_PREFIX;

@Service
@RequiredArgsConstructor
@Validated
public class AuthServiceImpl implements AuthService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final MailService mailService;
    private final MailMessageBuilder mailMessageBuilder;
    private final VerificationTokenService verificationTokenService;

    @Override
    @Transactional
    public void signUp(RegisterUserRequest request) {
        validateRegistrationRequest(request);
        User user = mapToUser(request);
        userRepository.save(user);

        String tokenValue = verificationTokenService.generateToken(user);
        String confirmationLink = CONFIRMATION_TOKEN_LINK_PREFIX + tokenValue;
        mailService.sendMail(new MailContent(
                user.getEmail(),
                CONFIRMATION_EMAIL_SUBJECT,
                mailMessageBuilder.getRegistrationMailContent(user.getUsername(), confirmationLink))
        );
    }


    private void validateRegistrationRequest(final RegisterUserRequest request) {
        if (!request.getPassword().equals(request.getRePassword())) {
            throw new PasswordsDoesNotMatchException("Passwords doesn't match");
        }
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new UsernameExistsException(
                    String.format("User with name %s already exists", request.getUsername()));
        }
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new EmailExistsException(
                    String.format("User with email %s already exists", request.getEmail()));
        }
    }

    private User mapToUser(final RegisterUserRequest request) {
        return User.builder()
                .email(request.getEmail())
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .enabled(false)
                .build();
    }

    @Override
    @Transactional
    public void verifyToken(String tokenValue) {
        VerificationToken verificationToken =
                verificationTokenService.getByTokenValue(tokenValue);
        User tokenOwner = verificationToken.getOwner();
        tokenOwner.setEnabled(true);
    }
}
