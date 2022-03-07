package com.zigix.todoitserver.service;

import com.zigix.todoitserver.config.jwt.JwtTokenUtil;
import com.zigix.todoitserver.domain.dto.*;
import com.zigix.todoitserver.domain.exception.EmailExistsException;
import com.zigix.todoitserver.domain.exception.PasswordsDoesNotMatchException;
import com.zigix.todoitserver.domain.exception.UsernameExistsException;
import com.zigix.todoitserver.domain.model.User;
import com.zigix.todoitserver.domain.model.VerificationToken;
import com.zigix.todoitserver.repository.UserRepository;
import com.zigix.todoitserver.service.mail.MailContent;
import com.zigix.todoitserver.service.mail.MailMessageBuilder;
import com.zigix.todoitserver.service.mail.MailService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpRequest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.MissingRequestHeaderException;

import javax.servlet.http.HttpServletRequest;

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
    private final JwtTokenUtil jwtTokenUtil;
    private final AuthenticationManager authenticationManager;

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

    @Transactional(readOnly = true)
    public User getLoggedUser() {
        return (User) SecurityContextHolder
                .getContext()
                .getAuthentication()
                .getPrincipal();
    }

    @Override
    @Transactional
    public AuthenticationResponse login(LoginRequest request) {
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword());
        Authentication authentication = authenticationManager.authenticate(authenticationToken);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        User loggedUser = getLoggedUser();
        String accessToken = jwtTokenUtil.generateAccessToken(loggedUser);
        String refreshToken = jwtTokenUtil.generateRefreshToken(loggedUser);
        UserView userView = UserView.builder()
                .id(loggedUser.getId())
                .email(loggedUser.getEmail())
                .username(loggedUser.getUsername())
                .createdDate(loggedUser.getCreatedDate())
                .lastModifiedDate(loggedUser.getLastModifiedDate())
                .enabled(loggedUser.isEnabled())
                .build();
        AccessTokensResponse tokens = new AccessTokensResponse(accessToken, refreshToken);
        return new AuthenticationResponse(userView, tokens);
    }

    @Override
    @Transactional
    public AccessTokensResponse refreshToken(HttpServletRequest request) {
            String refreshToken = getRefreshTokenFromRequest(request);
            jwtTokenUtil.validateJwt(refreshToken);
            String username = jwtTokenUtil.getUsername(refreshToken);
            User user = userRepository.findByUsername(username)
                    .orElseThrow(() ->
                            new UsernameNotFoundException(String.format("User with name %s not found", username)));
            String newAccessToken = jwtTokenUtil.generateAccessToken(user);
            return new AccessTokensResponse(newAccessToken, refreshToken);
    }

    private String getRefreshTokenFromRequest(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if (StringUtils.hasText(header) && header.startsWith("Bearer ")) {
            return header.substring("Bearer ".length());
        }
        return "";
    }
}
