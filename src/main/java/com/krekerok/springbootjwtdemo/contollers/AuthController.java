package com.krekerok.springbootjwtdemo.contollers;

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
import com.krekerok.springbootjwtdemo.services.UserDetailsImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "*", maxAge = 3600)
public class AuthController {

    private AuthenticationManager authenticationManager;
    private UserRepository userRespository;
    private RoleRepository roleRepository;
    private PasswordEncoder passwordEncoder;
    private JwtUtils jwtUtils;

    @Autowired
    public AuthController(AuthenticationManager authenticationManager, UserRepository userRespository, RoleRepository roleRepository, PasswordEncoder passwordEncoder, JwtUtils jwtUtils) {
        this.authenticationManager = authenticationManager;
        this.userRespository = userRespository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtils = jwtUtils;
    }

    @PostMapping("/signin")
    public ResponseEntity<?> authUser(@RequestBody LoginRequest loginRequest) {

        Authentication authentication = authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsername(),
                        loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        String jwt = jwtUtils.generateJwtToken(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());


        return ResponseEntity.ok(new JwtResponse(jwt, userDetails.getId(),
                                                 userDetails.getUsername(),
                                                 userDetails.getEmail(),
                                                 roles));
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@RequestBody SignupRequest signupRequest) {

        if (userRespository.existsByUsername(signupRequest.getUsername())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Username is exist"));
        }

        if (userRespository.existsByEmail(signupRequest.getEmail())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Email is exist"));
        }

        User user = new User(signupRequest.getUsername(),
                signupRequest.getEmail(),
                passwordEncoder.encode(signupRequest.getPassword()));

        Set<String> reqRoles = signupRequest.getRoles();
        Set<Role> roles = new HashSet<>();


        if (reqRoles == null) {

            Role userRole = roleRepository
                    .findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error, Role USER is not found"));
            roles.add(userRole);
        } else {


            reqRoles.forEach(r -> {
                switch (r) {
                    case "admin":


                        Role adminRole = roleRepository
                                .findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException("Error, Role ADMIN is not found"));
                        roles.add(adminRole);

                        break;
                    case "mod":


                        Role modRole = roleRepository
                                .findByName(ERole.ROLE_MODERATOR)
                                .orElseThrow(() -> new RuntimeException("Error, Role MODERATOR is not found"));
                        roles.add(modRole);

                        break;

                    default:


                        Role userRole = roleRepository
                                .findByName(ERole.ROLE_USER)
                                .orElseThrow(() -> new RuntimeException("Error, Role USER is not found"));
                        roles.add(userRole);
                }
            });
        }

        user.setRoles(roles);
        userRespository.save(user);


        return ResponseEntity.ok(new MessageResponse("User CREATED"));
    }
}
