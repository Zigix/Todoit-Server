package com.zigix.todoitserver.service;

import com.zigix.todoitserver.domain.model.User;

public interface VerificationTokenService {
    String generateToken(User user);
}
