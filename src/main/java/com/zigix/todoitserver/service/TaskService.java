package com.zigix.todoitserver.service;

import com.zigix.todoitserver.domain.dto.CreateTaskRequest;

public interface TaskService {
    void createTask(CreateTaskRequest request);
}
