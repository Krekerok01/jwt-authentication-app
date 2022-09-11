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
import com.krekerok.springbootjwtdemo.services.UserService;
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


    private UserService userService;

    @Autowired
    public AuthController(UserService userService) {
        this.userService = userService;
    }


    @PostMapping("/signin")
    public ResponseEntity<?> authUser(@RequestBody LoginRequest loginRequest) {
        return userService.authUser(loginRequest);
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@RequestBody SignupRequest signupRequest) {
        return userService.registerUser(signupRequest);
    }
}
