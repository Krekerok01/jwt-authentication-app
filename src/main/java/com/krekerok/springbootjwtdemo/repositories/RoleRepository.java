package com.krekerok.springbootjwtdemo.repositories;

import com.krekerok.springbootjwtdemo.models.ERole;
import com.krekerok.springbootjwtdemo.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {

    Optional<Role> findByName(ERole name);
}
