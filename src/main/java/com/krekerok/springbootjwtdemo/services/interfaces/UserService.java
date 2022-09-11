package com.krekerok.springbootjwtdemo.services.interfaces;

import com.krekerok.springbootjwtdemo.pojo.LoginRequest;
import com.krekerok.springbootjwtdemo.pojo.SignupRequest;
import org.springframework.http.ResponseEntity;

public interface UserService {

    ResponseEntity<?> authUser(LoginRequest loginRequest);

    ResponseEntity<?> registerUser(SignupRequest signupRequest);
}
