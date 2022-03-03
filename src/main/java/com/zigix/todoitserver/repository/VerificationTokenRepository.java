package com.zigix.todoitserver.repository;

import com.zigix.todoitserver.domain.model.VerificationToken;
import org.springframework.data.jpa.repository.JpaRepository;

public interface VerificationTokenRepository extends JpaRepository<VerificationToken, Long> {
}
