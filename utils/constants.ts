/**
 * Application Constants
 *
 * This file centralizes all constants used across the application.
 * Import from this file instead of defining constants in individual files.
 */

// Authentication Constants
export const COOKIE_NAME = "auth_token";
export const REFRESH_COOKIE_NAME = "refresh_token";
export const COOKIE_MAX_AGE = 20; // 20 seconds
export const JWT_EXPIRATION_TIME = "20s"; // 20 seconds
export const REFRESH_TOKEN_EXPIRY = "30d"; // 30 days
export const REFRESH_TOKEN_MAX_AGE = 30 * 24 * 60 * 60; // 30 days in seconds

// Refresh Token Constants
export const REFRESH_BEFORE_EXPIRY_SEC = 60; // Refresh token 1 minute before expiry

// Google OAuth Constants
export const GOOGLE_CLIENT_ID = '99090385428-o7c34t5u6703o1paid6qtvfac0be7rd5.apps.googleusercontent.com';
export const GOOGLE_CLIENT_SECRET = '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';
export const GOOGLE_REDIRECT_URI = `http://localhost:8081/api/auth/callback`;
export const GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth";

// Apple OAuth Constants
export const APPLE_CLIENT_ID = "com.beto.expoauthexample.web";
export const APPLE_CLIENT_SECRET = process.env.APPLE_CLIENT_SECRET!;
export const APPLE_REDIRECT_URI = `${process.env.EXPO_PUBLIC_BASE_URL}/api/auth/apple/callback`;
export const APPLE_AUTH_URL = "https://appleid.apple.com/auth/authorize";

// Environment Constants
export const BASE_URL = 'http://localhost:8081';
export const APP_SCHEME = 'http://localhost:8081';//'betoauthexample://';
export const JWT_SECRET = 'wYz4X93hZ6tv0e0jPZ+6A9XjNq3CW5lT1RcfUxABNnQ='

// Cookie Settings
export const COOKIE_OPTIONS = {
  httpOnly: true,
  secure: true,
  sameSite: "Lax" as const,
  path: "/",
  maxAge: COOKIE_MAX_AGE,
};

export const REFRESH_COOKIE_OPTIONS = {
  httpOnly: true,
  secure: true,
  sameSite: "Lax" as const,
  path: "/api/auth/refresh", // Restrict to refresh endpoint only
  maxAge: REFRESH_TOKEN_MAX_AGE,
};
