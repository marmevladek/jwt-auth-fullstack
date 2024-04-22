package com.project.jwtauthspring.service;

import com.project.jwtauthspring.payload.request.LoginRequest;
import com.project.jwtauthspring.payload.request.SignupRequest;
import com.project.jwtauthspring.payload.response.JwtResponse;
import com.project.jwtauthspring.payload.response.MessageResponse;


public interface AuthService {

    JwtResponse authenticateUser(LoginRequest loginRequest);

    MessageResponse registerUser(SignupRequest signupRequest);
}
