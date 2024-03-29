package com.zigix.todoitserver.service;

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
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {
    public static final String CONFIRMATION_TOKEN_LINK_PREFIX = "http://localhost:8080/api/v1/auth/verify?token=";
    public static final String CONFIRMATION_EMAIL_SUBJECT = "Confirm your account";

    public static final String BEARER_PREFIX = "Bearer ";

    private final UserRepository userRepository;
    private final MailService mailService;
    private final MailMessageBuilder mailMessageBuilder;
    private final VerificationTokenService verificationTokenService;
    private final JwtTokenUtil jwtTokenUtil;
    private final UserMapper userMapper;

    @Override
    @Transactional
    public void signUp(RegisterUserRequest request) {
        validateRegistrationRequest(request);
        User user = userMapper.mapToUser(request);
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

    @Override
    @Transactional
    public void verifyUserByToken(String tokenValue) {
        VerificationToken verificationToken =
                verificationTokenService.getByTokenValue(tokenValue);
        User tokenOwner = verificationToken.getOwner();
        if (tokenOwner.isEnabled()) {
            throw new UserVerifiedException("User already verified");
        }
        tokenOwner.setEnabled(true);
    }

    @Transactional(readOnly = true)
    public User getLoggedUser() {
        return (User) SecurityContextHolder
                .getContext()
                .getAuthentication()
                .getPrincipal();
    }

    @Override
    @Transactional
    public AccessTokensResponse refreshToken(HttpServletRequest request) {
        String refreshToken = getRefreshTokenFromRequest(request);
        jwtTokenUtil.validateJwt(refreshToken);
        if (!jwtTokenUtil.getTokenType(refreshToken).equals(JwtTokenUtil.REFRESH_TOKEN_NAME)) {
            throw new InvalidTokenTypeException("Invalid token type");
        }
        String username = jwtTokenUtil.getUsername(refreshToken);

        User user = userRepository.findByUsername(username)
                .orElseThrow(() ->
                        new UsernameNotFoundException(String.format("User with name %s not found", username)));
        String newAccessToken = jwtTokenUtil.generateAccessToken(user);
        return new AccessTokensResponse(newAccessToken, refreshToken);
    }

    private String getRefreshTokenFromRequest(HttpServletRequest request) {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (StringUtils.hasText(header) && header.startsWith(BEARER_PREFIX)) {
            return header.substring(BEARER_PREFIX.length());
        }
        return "";
    }
}
