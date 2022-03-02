package com.zigix.todoitserver.domain.exception;

public class PasswordsDoesNotMatchException extends RuntimeException {
    public PasswordsDoesNotMatchException(String message) {
        super(message);
    }
}
