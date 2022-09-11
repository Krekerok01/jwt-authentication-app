package com.krekerok.springbootjwtdemo.services;

import com.krekerok.springbootjwtdemo.configs.jwt.JwtUtils;
import com.krekerok.springbootjwtdemo.models.ERole;
import com.krekerok.springbootjwtdemo.models.Role;
import com.krekerok.springbootjwtdemo.models.User;
import com.krekerok.springbootjwtdemo.pojo.JwtResponse;
import com.krekerok.springbootjwtdemo.pojo.LoginRequest;
import com.krekerok.springbootjwtdemo.pojo.MessageResponse;
import com.krekerok.springbootjwtdemo.pojo.SignupRequest;
import com.krekerok.springbootjwtdemo.repositories.RoleRepository;
import com.krekerok.springbootjwtdemo.repositories.UserRepository;
import com.krekerok.springbootjwtdemo.services.interfaces.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class UserServiceImpl implements UserService {

    private UserRepository userRespository;
    private RoleRepository roleRepository;
    private PasswordEncoder passwordEncoder;
    private AuthenticationManager authenticationManager;
    private JwtUtils jwtUtils;

    @Autowired
    public UserServiceImpl(UserRepository userRespository, RoleRepository roleRepository, PasswordEncoder passwordEncoder, AuthenticationManager authenticationManager, JwtUtils jwtUtils) {
        this.userRespository = userRespository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.jwtUtils = jwtUtils;
    }

    @Override
    public ResponseEntity<?> authUser(LoginRequest loginRequest) {

        Authentication authentication = getAuthentication(loginRequest);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        List<String> roles = getRolesList(userDetails);

        return ResponseEntity.ok(new JwtResponse(jwt, userDetails.getId(), userDetails.getUsername(), userDetails.getEmail(), roles));
    }

    @Override
    public ResponseEntity<?> registerUser(SignupRequest signupRequest) {
        if (userRespository.existsByUsername(signupRequest.getUsername()))
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Username is exist"));

        if (userRespository.existsByEmail(signupRequest.getEmail()))
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Email is exist"));

        Set<Role> roles = fillRolesListWithDataFromRequestRolesList(signupRequest.getRoles());
        createAndSaveUser(signupRequest, roles);

        return ResponseEntity.ok(new MessageResponse("User CREATED"));
    }



    private Authentication getAuthentication(LoginRequest loginRequest) {
        return authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
    }

    private List<String> getRolesList(UserDetailsImpl userDetails) {
        return userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());
    }


    private void createAndSaveUser(SignupRequest signupRequest, Set<Role> roles) {
        User user = new User(signupRequest.getUsername(), signupRequest.getEmail(), passwordEncoder.encode(signupRequest.getPassword()));
        user.setRoles(roles);
        userRespository.save(user);
    }

    private Set<Role> fillRolesListWithDataFromRequestRolesList(Set<String> reqRoles){
        Set<Role> roles = new HashSet<>();
        if (reqRoles == null) {
            roles.add(getRoleFromEnum(ERole.ROLE_USER));
        } else {
            reqRoles.forEach(r -> {
                switch (r) {
                    case "admin":
                        roles.add(getRoleFromEnum(ERole.ROLE_ADMIN));
                        break;
                    case "mod":
                        roles.add(getRoleFromEnum(ERole.ROLE_MODERATOR));
                        break;
                    default:
                        roles.add(getRoleFromEnum(ERole.ROLE_USER));
                }
            });
        }
        return roles;
    }

    private Role getRoleFromEnum(ERole eRole){
        return roleRepository
                .findByName(eRole)
                .orElseThrow(() -> new RuntimeException(String.format("Error, Role %s is not found",  eRole.name())));
    }
}
