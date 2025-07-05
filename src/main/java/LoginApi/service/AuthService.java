package LoginApi.service;

import LoginApi.auth.JwtAuthenticationFilter;
import LoginApi.auth.JwtTokenUtil;
import LoginApi.model.User;
import LoginApi.repo.UserRepo;
import LoginApi.requestDTO.LoginRequest;
import LoginApi.requestDTO.RegisterRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final UserRepo userRepo;
    private final JwtTokenUtil jwtTokenUtil;
    private final PasswordEncoder passwordEncoder;

    public String registerUser(RegisterRequest request){
        if (userRepo.findByEmail(request.getEmail()).isPresent()){
            throw new RuntimeException("User Already exists");
        }
        User user = new User();
        user.setEmail(request.getEmail());
        user.setName(request.getName());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        userRepo.save(user);
        return jwtTokenUtil.generateToken(user.getEmail());
    }
    public String LoginUser(LoginRequest request){
        User user = userRepo.findByEmail(request.getEmail()).orElseThrow(()->new RuntimeException("Invalid Credentials"));
        if (!passwordEncoder.matches(request.getPassword(),user.getPassword())){
            throw new RuntimeException("Invalid Credentials");
        }
        return jwtTokenUtil.generateToken(user.getEmail());

    }
    public User getUser(String email){
        return userRepo.findByEmail(email).orElseThrow(()->new RuntimeException("User not found"));
    }

}
