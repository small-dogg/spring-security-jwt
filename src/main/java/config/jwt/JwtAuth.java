package config.jwt;

import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import lombok.Value;

@Value(staticConstructor = "of")
public class JwtAuth {
    private final Claims claims;
    private final boolean valid;
}
