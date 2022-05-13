package com.zigix.todoitserver.domain.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ApiErrorResponse {
    private long timestamp;
    private int status;
    private List<String> messages = new ArrayList<>();
}
