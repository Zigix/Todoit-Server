package com.zigix.todoitserver.service;

import com.zigix.todoitserver.domain.dto.AccessTokensResponse;
import com.zigix.todoitserver.domain.dto.RegisterUserRequest;
import com.zigix.todoitserver.domain.model.User;

import javax.servlet.http.HttpServletRequest;

public interface AuthService {
    void signUp(RegisterUserRequest request);

    void verifyToken(String tokenValue);

    User getLoggedUser();

    AccessTokensResponse refreshToken(HttpServletRequest request);
}
