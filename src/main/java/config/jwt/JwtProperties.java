package config.jwt;

import lombok.AllArgsConstructor;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.ConstructorBinding;
import org.springframework.validation.annotation.Validated;

@Validated
@AllArgsConstructor
@ConstructorBinding
@ConfigurationProperties(prefix = "jwt.secret")
public class JwtProperties {

    private final String secret;
}
