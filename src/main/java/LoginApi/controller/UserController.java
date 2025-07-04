package LoginApi.controller;

import LoginApi.auth.JwtTokenUtil;
import LoginApi.model.User;
import LoginApi.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/user")
public class UserController {
    private final AuthService authService;
    private final JwtTokenUtil jwtTokenUtil;

    @GetMapping("/profile")
    public ResponseEntity<User> getProfile(HttpServletRequest request){
        String authHeader = request.getHeader("Authorization");
        String token = authHeader.substring(7);
        String email = jwtTokenUtil.getUserName(token);
        User user = authService.getUser(email);
        return ResponseEntity.ok(user);
    }
}
