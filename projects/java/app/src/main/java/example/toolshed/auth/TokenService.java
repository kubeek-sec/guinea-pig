package example.toolshed.auth;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Optional;

import javax.crypto.SecretKey;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import example.toolshed.store.Member;
import example.toolshed.store.Repositories;

/** Issues and reads the bearer tokens of a member session. */
@Service
public class TokenService {

    private final Repositories repo;
    private final BCryptPasswordEncoder encoder;
    private final long ttlSeconds;

    public TokenService(Repositories repo, BCryptPasswordEncoder encoder,
                        @Value("${toolshed.token-ttl:3600}") long ttlSeconds) {
        this.repo = repo;
        this.encoder = encoder;
        this.ttlSeconds = ttlSeconds;
    }

    private SecretKey signingKey() {
        String key = System.getenv("TOOLSHED_TOKEN_KEY");
        if (key == null || key.isBlank()) {
            throw new IllegalStateException("TOOLSHED_TOKEN_KEY is not set");
        }
        return Keys.hmacShaKeyFor(key.getBytes(StandardCharsets.UTF_8));
    }

    public String issue(Member member) {
        Date now = new Date();
        return Jwts.builder()
                .subject(String.valueOf(member.id()))
                .claim("email", member.email())
                .claim("role", member.role())
                .issuedAt(now)
                .expiration(new Date(now.getTime() + ttlSeconds * 1000))
                .signWith(signingKey())
                .compact();
    }

    public Optional<Member> authenticate(String email, String password) {
        return repo.memberByEmail(email)
                .filter(m -> encoder.matches(password, m.password()));
    }

    public Optional<Member> fromHeader(String authorization) {
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            return Optional.empty();
        }
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(signingKey())
                    .build()
                    .parseSignedClaims(authorization.substring(7))
                    .getPayload();
            return repo.member(Long.parseLong(claims.getSubject()));
        } catch (JwtException | NumberFormatException e) {
            return Optional.empty();
        }
    }
}
