package com.zigix.todoitserver.service;

import com.zigix.todoitserver.domain.dto.AccessTokensResponse;
import com.zigix.todoitserver.domain.dto.AuthenticationResponse;
import com.zigix.todoitserver.domain.dto.LoginRequest;
import com.zigix.todoitserver.domain.dto.RegisterUserRequest;
import com.zigix.todoitserver.domain.model.User;

import javax.servlet.http.HttpServletRequest;

public interface AuthService {
    void signUp(RegisterUserRequest request);

    void verifyToken(String tokenValue);

    AuthenticationResponse login(LoginRequest request);

    User getLoggedUser();

    AccessTokensResponse refreshToken(HttpServletRequest request);
}
