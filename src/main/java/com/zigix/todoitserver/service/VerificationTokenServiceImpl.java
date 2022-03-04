package com.zigix.todoitserver.service;

import com.zigix.todoitserver.domain.exception.VerificationTokenNotFoundException;
import com.zigix.todoitserver.domain.model.User;
import com.zigix.todoitserver.domain.model.VerificationToken;
import com.zigix.todoitserver.repository.VerificationTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class VerificationTokenServiceImpl implements VerificationTokenService {
    private final VerificationTokenRepository verificationTokenRepository;

    @Override
    public String generateToken(User user) {
        VerificationToken verificationToken = new VerificationToken();
        verificationToken.setToken(UUID.randomUUID().toString());
        verificationToken.setOwner(user);
        verificationTokenRepository.save(verificationToken);

        return verificationToken.getToken();
    }

    @Override
    public VerificationToken getByTokenValue(String tokenValue) {
        return verificationTokenRepository.findByToken(tokenValue)
                .orElseThrow(() ->
                        new VerificationTokenNotFoundException(
                                String.format("Verification token with value %s not found", tokenValue)));
    }
}
