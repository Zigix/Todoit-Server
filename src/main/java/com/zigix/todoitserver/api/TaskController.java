package com.zigix.todoitserver.api;

import com.zigix.todoitserver.domain.dto.CreateTaskRequest;
import com.zigix.todoitserver.service.TaskService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;

@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
public class TaskController {
    private final TaskService taskService;

    @PostMapping("/tasks")
    public ResponseEntity<Void> createTask(@RequestBody @Valid CreateTaskRequest request) {
        taskService.createTask(request);
        return ResponseEntity.noContent().build();
    }
}
