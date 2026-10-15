package example.toolshed.web;

import java.time.LocalDate;
import java.util.List;
import java.util.Map;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import example.toolshed.store.Member;
import example.toolshed.store.Rental;
import example.toolshed.store.Repositories;
import example.toolshed.store.Tool;

/** Taking tools out and bringing them back. */
@RestController
public class RentalController {

    private static final int DEFAULT_DAYS = 7;

    public record TakeOut(Long toolId, Integer days, String notes) {
    }

    private final Repositories repo;
    private final Sessions sessions;

    public RentalController(Repositories repo, Sessions sessions) {
        this.repo = repo;
        this.sessions = sessions;
    }

    @GetMapping("/api/rentals")
    public Map<String, List<Rental>> myRentals(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization) {
        Member member = sessions.required(authorization);
        return Map.of("rentals", repo.rentalsOf(member.id()));
    }

    @PostMapping("/api/rentals")
    public ResponseEntity<Map<String, Object>> takeOut(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization,
            @RequestBody TakeOut body) {
        Member member = sessions.required(authorization);
        Tool tool = repo.tool(body.toolId() == null ? -1 : body.toolId())
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "no such tool"));
        if (!tool.available()) {
            throw new ApiException(HttpStatus.CONFLICT, "already out");
        }
        int days = body.days() == null || body.days() <= 0 ? DEFAULT_DAYS : body.days();
        LocalDate today = LocalDate.now();
        LocalDate due = today.plusDays(days);
        long id = repo.createRental(member.id(), tool.id(), today.toString(), due.toString(),
                body.notes() == null ? "" : body.notes());
        repo.setToolAvailable(tool.id(), false);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(Map.of("id", id, "due_on", due.toString()));
    }

    @PostMapping("/api/rentals/{id}/return")
    public Map<String, String> bringBack(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization,
            @PathVariable long id) {
        Member member = sessions.required(authorization);
        Rental rental = repo.rentalOf(id, member.id())
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "no such rental"));
        repo.closeRental(rental.id());
        repo.setToolAvailable(rental.toolId(), true);
        return Map.of("status", "returned");
    }
}
