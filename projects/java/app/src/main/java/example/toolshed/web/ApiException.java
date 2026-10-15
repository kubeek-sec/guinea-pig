package example.toolshed.web;

import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/** Turns the controllers' refusals into a small JSON body. */
public class ApiException extends RuntimeException {

    private final HttpStatus status;

    public ApiException(HttpStatus status, String message) {
        super(message);
        this.status = status;
    }

    public HttpStatus status() {
        return status;
    }

    @RestControllerAdvice
    public static class Handler {
        @ExceptionHandler(ApiException.class)
        public ResponseEntity<Map<String, String>> handle(ApiException e) {
            return ResponseEntity.status(e.status()).body(Map.of("error", e.getMessage()));
        }
    }
}
