package config.jwt;

import lombok.Value;
import org.springframework.security.core.Authentication;

@Value(staticConstructor = "of")
public class JwtAuth {
    private final Claims claims;
    private final Authentication authentication;
}
