package com.aniview.authusers.dto;

public record LoginRequestDto(
        String email,
        String password) {
}
