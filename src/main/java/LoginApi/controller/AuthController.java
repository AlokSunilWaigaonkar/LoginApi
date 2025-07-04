package LoginApi.controller;

import LoginApi.requestDTO.LoginRequest;
import LoginApi.requestDTO.RegisterRequest;
import LoginApi.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.apache.catalina.connector.Response;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
public class AuthController {
    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<Map<String,String>> registerUser(@RequestBody RegisterRequest request){
        String token = authService.registerUser(request);
        return ResponseEntity.ok(Map.of("token",token));
    }

    public ResponseEntity<Map<String,String>> loginUser(@RequestBody LoginRequest request){
        String token = authService.LoginUser(request);
        return ResponseEntity.ok(Map.of("token",token));
    }
}
