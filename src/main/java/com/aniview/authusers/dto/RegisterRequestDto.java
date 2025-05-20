package com.aniview.authusers.dto;

public record RegisterRequestDto(
        String email,
        String name,
        String lastname,
        String username,
        String image,
        String password) {
}
