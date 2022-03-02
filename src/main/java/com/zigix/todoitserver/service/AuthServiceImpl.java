package com.zigix.todoitserver.service;

import com.zigix.todoitserver.domain.dto.RegisterUserRequest;
import com.zigix.todoitserver.domain.exception.EmailExistsException;
import com.zigix.todoitserver.domain.exception.PasswordsDoesNotMatchException;
import com.zigix.todoitserver.domain.exception.UsernameExistsException;
import com.zigix.todoitserver.domain.model.User;
import com.zigix.todoitserver.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.validation.Valid;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    @Transactional
    public void signUp(@Valid RegisterUserRequest request) {
        validateRegistrationRequest(request);
        userRepository.save(mapToUser(request));
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
}
