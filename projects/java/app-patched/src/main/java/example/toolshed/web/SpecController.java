package example.toolshed.web;

import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/** Serves the OpenAPI document so API clients can import the endpoints. */
@RestController
public class SpecController {

    @GetMapping(value = "/openapi.yml", produces = "application/yaml")
    public ResponseEntity<Resource> spec() {
        return ResponseEntity.ok(new ClassPathResource("openapi.yml"));
    }
}
