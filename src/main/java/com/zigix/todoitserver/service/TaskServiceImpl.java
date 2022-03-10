package com.zigix.todoitserver.service;

import com.zigix.todoitserver.domain.dto.CreateTaskRequest;
import com.zigix.todoitserver.domain.mapper.TaskMapper;
import com.zigix.todoitserver.domain.model.Task;
import com.zigix.todoitserver.domain.model.User;
import com.zigix.todoitserver.repository.TaskRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class TaskServiceImpl implements TaskService {
    private final AuthService authService;
    private final TaskRepository taskRepository;
    private final TaskMapper taskMapper;

    @Override
    @Transactional
    public void createTask(CreateTaskRequest request) {
        User taskOwner = authService.getLoggedUser();
        Task task = taskMapper.mapToTask(request, taskOwner);
        taskRepository.save(task);
    }
}
