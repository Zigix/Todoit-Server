package com.zigix.todoitserver.api.handler;

import com.zigix.todoitserver.domain.dto.ApiErrorResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.ObjectError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.util.List;

@ControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiErrorResponse> handleMethodArgumentNotValidException(MethodArgumentNotValidException ex) {
        ApiErrorResponse apiErrorResponse = new ApiErrorResponse();
        apiErrorResponse.setTimestamp(System.currentTimeMillis());
        apiErrorResponse.setStatus(HttpStatus.BAD_REQUEST.value());

        List<ObjectError> errors = ex.getAllErrors();
        for (ObjectError error : errors) {
            apiErrorResponse.getMessages().add(error.getDefaultMessage());
        }

        return ResponseEntity.badRequest().body(apiErrorResponse);
    }

    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<ApiErrorResponse> handlerValidationException(RuntimeException ex) {
        ApiErrorResponse apiErrorResponse = new ApiErrorResponse();
        apiErrorResponse.setTimestamp(System.currentTimeMillis());
        apiErrorResponse.setStatus(HttpStatus.BAD_REQUEST.value());
        apiErrorResponse.getMessages().add(ex.getMessage());
        return ResponseEntity.badRequest().body(apiErrorResponse);
    }
}
