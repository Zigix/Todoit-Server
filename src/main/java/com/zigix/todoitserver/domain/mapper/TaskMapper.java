package com.zigix.todoitserver.domain.mapper;

import com.zigix.todoitserver.domain.dto.CreateTaskRequest;
import com.zigix.todoitserver.domain.model.Task;
import com.zigix.todoitserver.domain.model.User;
import org.springframework.stereotype.Component;

@Component
public class TaskMapper {

    public Task mapToTask(CreateTaskRequest request, User taskOwner) {
        return Task.builder()
                .title(request.getTitle())
                .description(request.getDescription())
                .deadline(request.getDeadline())
                .done(false)
                .owner(taskOwner)
                .build();
    }
}
