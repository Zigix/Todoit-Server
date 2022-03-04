package com.zigix.todoitserver.service;

import com.zigix.todoitserver.domain.dto.RegisterUserRequest;

public interface AuthService {
    void signUp(RegisterUserRequest request);

    void verifyToken(String tokenValue);
}
