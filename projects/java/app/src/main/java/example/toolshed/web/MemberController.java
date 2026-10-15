package example.toolshed.web;

import java.util.Map;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import example.toolshed.auth.TokenService;
import example.toolshed.store.Member;
import example.toolshed.store.Repositories;

/** Member accounts and sign-in. */
@RestController
public class MemberController {

    public record Credentials(String email, String password) {
    }

    private final TokenService tokens;
    private final Sessions sessions;
    private final Repositories repo;

    public MemberController(TokenService tokens, Sessions sessions, Repositories repo) {
        this.tokens = tokens;
        this.sessions = sessions;
        this.repo = repo;
    }

    @PostMapping("/api/session")
    public Map<String, String> signIn(@RequestBody Credentials body) {
        Member member = tokens.authenticate(
                        body.email() == null ? "" : body.email(),
                        body.password() == null ? "" : body.password())
                .orElseThrow(() -> new ApiException(HttpStatus.UNAUTHORIZED, "bad credentials"));
        return Map.of("token", tokens.issue(member), "role", member.role());
    }

    @GetMapping("/api/members/me")
    public Member whoami(@RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization) {
        return sessions.required(authorization);
    }

    @GetMapping("/api/members/{id}")
    public Member getMember(@RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization,
                            @PathVariable long id) {
        sessions.staff(authorization);
        return repo.member(id)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "no such member"));
    }
}
