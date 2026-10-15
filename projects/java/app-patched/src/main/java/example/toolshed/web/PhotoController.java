package example.toolshed.web;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import example.toolshed.store.Member;

/** Condition photos attached to a rental. */
@RestController
public class PhotoController {

    private static final Set<String> ACCEPTED = Set.of(".jpg", ".jpeg", ".png", ".webp");
    private static final SecureRandom RANDOM = new SecureRandom();

    private final Path uploads;
    private final Sessions sessions;

    public PhotoController(@Value("${toolshed.uploads}") String uploads, Sessions sessions) throws IOException {
        this.uploads = Paths.get(uploads).toAbsolutePath().normalize();
        this.sessions = sessions;
        Files.createDirectories(this.uploads);
    }

    private static String extensionOf(String filename) {
        if (filename == null) {
            return "";
        }
        int dot = filename.lastIndexOf('.');
        return dot < 0 ? "" : filename.substring(dot).toLowerCase(Locale.ROOT);
    }

    @PostMapping("/api/photos")
    public ResponseEntity<Map<String, String>> upload(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization,
            @RequestParam("photo") MultipartFile photo) throws IOException {
        Member member = sessions.required(authorization);
        if (photo.isEmpty()) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "no photo");
        }
        String ext = extensionOf(photo.getOriginalFilename());
        if (!ACCEPTED.contains(ext)) {
            throw new ApiException(HttpStatus.BAD_REQUEST, (ext.isEmpty() ? "file" : ext) + " not accepted");
        }
        byte[] token = new byte[16];
        RANDOM.nextBytes(token);
        String name = HexFormat.of().formatHex(token) + ext;
        try (var in = photo.getInputStream()) {
            Files.copy(in, uploads.resolve(name), StandardCopyOption.REPLACE_EXISTING);
        }
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(Map.of("name", name, "owner", member.email()));
    }

    @GetMapping("/api/photos/{name}")
    public ResponseEntity<Resource> fetch(@PathVariable String name) {
        Path file = uploads.resolve(Paths.get(name).getFileName()).normalize();
        if (!file.startsWith(uploads) || !Files.isRegularFile(file)) {
            throw new ApiException(HttpStatus.NOT_FOUND, "no such photo");
        }
        return ResponseEntity.ok()
                .header("X-Content-Type-Options", "nosniff")
                .body(new FileSystemResource(file));
    }
}
