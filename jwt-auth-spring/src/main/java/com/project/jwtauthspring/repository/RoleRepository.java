package com.project.jwtauthspring.repository;

import com.project.jwtauthspring.models.ERole;
import com.project.jwtauthspring.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Integer> {
    Optional<Role> findByName(ERole name);
}
