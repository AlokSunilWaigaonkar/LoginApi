package LoginApi.auth;

import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.Claims;

import javax.crypto.spec.SecretKeySpec;

@Component
public class JwtTokenUtil {
    @Value("${JWT_SECRET}")
    private String SECRET_KEY;
    private final long ACCESS_TOKEN_EXPIRATION = 60*60*1000;

    public Key getSigningKey(){
        byte[] bytes = SECRET_KEY.getBytes(StandardCharsets.UTF_8);
        return new SecretKeySpec(bytes , SignatureAlgorithm.HS256.getJcaName());
    }

    public String generateToken(String username){
        return  Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis()+ACCESS_TOKEN_EXPIRATION))
                .signWith(getSigningKey(),SignatureAlgorithm.HS256)
                .compact();
    }

    public boolean isTokenExpired(String token){
        try{
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
            System.out.println("Token valid for user " + claims.getSubject());
            return !claims.getExpiration().before(new Date());
        }
        catch (Exception e){
            System.out.println("Token invalid for user "+e.getMessage());
            return false;
        }
    }
    public boolean validateToken(String token , UserDetails userDetails){
        String userName = getUserName(token);
        boolean notExpired = isTokenExpired(token);
        return userName.equals(userDetails.getUsername()) && notExpired;
    }
    public String getUserName(String token){
        try{
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
            return claims.getSubject();
        }
        catch (Exception e){
            return null;
        }
    }


}
