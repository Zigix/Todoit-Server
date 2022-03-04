package com.zigix.todoitserver.service;

import com.zigix.todoitserver.domain.model.User;
import com.zigix.todoitserver.domain.model.VerificationToken;

public interface VerificationTokenService {
    String generateToken(User user);
    VerificationToken getByTokenValue(String tokenValue);
}
