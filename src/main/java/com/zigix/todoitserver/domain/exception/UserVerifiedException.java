package com.zigix.todoitserver.domain.exception;

public class UserVerifiedException extends RuntimeException {
    public UserVerifiedException(String message) {
        super(message);
    }
}
