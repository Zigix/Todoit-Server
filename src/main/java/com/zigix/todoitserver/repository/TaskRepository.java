package com.zigix.todoitserver.repository;

import com.zigix.todoitserver.domain.model.Task;
import org.springframework.data.jpa.repository.JpaRepository;

public interface TaskRepository extends JpaRepository<Task, Long> {
}
