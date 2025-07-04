package LoginApi.repo;

import LoginApi.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepo extends JpaRepository<Integer, User> {
    Optional<Object> findByEmail(String email);
}
