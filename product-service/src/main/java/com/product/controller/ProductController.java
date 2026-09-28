package com.product.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/products")
public class ProductController {

    @PostMapping
    public ResponseEntity<Map<String, Object>> createProduct(
            @RequestHeader(value = "X-User-Role", required = false) String role,
            @RequestHeader(value = "X-User-Id", required = false) String userId,
            @RequestBody(required = false) Map<String, Object> body) {
        return authorizeAndHandle(role, userId, "Product created successfully");
    }

    @GetMapping
    public ResponseEntity<Map<String, Object>> getProducts(
            @RequestHeader(value = "X-User-Role", required = false) String role,
            @RequestHeader(value = "X-User-Id", required = false) String userId) {
        return authorizeAndHandle(role, userId, "Product list retrieved successfully");
    }

    private ResponseEntity<Map<String, Object>> authorizeAndHandle(String role, String userId, String successMessage) {
        if ("ADMIN".equalsIgnoreCase(role)) {
            return ResponseEntity.ok(Map.of(
                    "status", 200,
                    "message", successMessage,
                    "userId", userId != null ? userId : "unknown",
                    "role", role
            ));
        }

        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of(
                "status", 403,
                "error", "Forbidden",
                "message", "Access Denied: Requires ADMIN role",
                "userId", userId != null ? userId : "unknown",
                "role", role != null ? role : "none"
        ));
    }
}
