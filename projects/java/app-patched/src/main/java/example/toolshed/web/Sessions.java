package example.toolshed.web;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import example.toolshed.auth.TokenService;
import example.toolshed.store.Member;

/** Resolves the member behind a request and enforces the staff role. */
@Component
public class Sessions {

    private final TokenService tokens;

    public Sessions(TokenService tokens) {
        this.tokens = tokens;
    }

    public Member required(String authorization) {
        return tokens.fromHeader(authorization)
                .orElseThrow(() -> new ApiException(HttpStatus.UNAUTHORIZED, "authentication required"));
    }

    public Member staff(String authorization) {
        Member member = required(authorization);
        if (!"staff".equals(member.role())) {
            throw new ApiException(HttpStatus.FORBIDDEN, "staff only");
        }
        return member;
    }
}
