import * as jose from "jose";
import {
  COOKIE_NAME,
  REFRESH_COOKIE_NAME,
  COOKIE_MAX_AGE,
  JWT_EXPIRATION_TIME,
  JWT_SECRET,
  COOKIE_OPTIONS,
  REFRESH_TOKEN_EXPIRY,
  REFRESH_COOKIE_OPTIONS,
} from "@/utils/constants";
import { OAuth2Client } from "google-auth-library";
import fs from "fs/promises";
import path from "path";
import { AuthUser } from "@/utils/middleware";
import { serialize } from "cookie";

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;

//const dbPath = path.resolve(process.cwd(), "db.json");
const dbPath= "E:/MobileApp/expo-oauth-example/db.json"

async function readDb() {
  try {
    const data = await fs.readFile(dbPath, "utf-8");
    return JSON.parse(data);
  } catch (error: any) {
    if (error.code === "ENOENT") {
      return { users: [] };
    }
    throw error;
  }
}

const oauth2Client = new OAuth2Client(
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET
);

/**
 * Refresh API endpoint
 *
 * This endpoint refreshes the user's authentication token using a refresh token.
 * It implements token rotation - each refresh generates a new refresh token.
 * For web clients, it refreshes the cookies.
 * For native clients, it returns new tokens.
 */
export async function POST(request: Request) {
  if (!JWT_SECRET) {
    console.error("JWT_SECRET is not configured");
    return Response.json({ error: "Server misconfiguration" }, { status: 500 });
  }

  let refreshToken: string | null = null;
  const contentType = request.headers.get("content-type") || "";
  const body = contentType.includes("application/json")
    ? await request.json()
    : {};
  const platform = body.platform || "native";

  if (platform === "native") {
    refreshToken = body.refreshToken;
  } else {
    const cookieHeader = request.headers.get("cookie");
    if (cookieHeader) {
      const cookies = cookieHeader.split(";").reduce((acc, cookie) => {
        const [key, value] = cookie.trim().split("=");
        acc[key.trim()] = value;
        return acc;
      }, {} as Record<string, string>);
      refreshToken = cookies[REFRESH_COOKIE_NAME];
    }
  }

  if (!refreshToken) {
    return Response.json(
      { error: "Authentication required - no refresh token" },
      { status: 401 }
    );
  }

  try {
    const decoded = await jose.jwtVerify(
      refreshToken,
      new TextEncoder().encode(JWT_SECRET)
    );

    const payload = decoded.payload as AuthUser & { id: string };
    const userId = payload.id;
    const provider = payload.provider;

    if (!userId) {
      return Response.json(
        { error: "Invalid token, missing subject" },
        { status: 401 }
      );
    }

    let userPayload: AuthUser;

    if (provider === "google") {
      if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) {
        return Response.json(
          { error: "Google credentials not configured" },
          { status: 500 }
        );
      }
      const db = await readDb();
      const user = db.users.find((u: any) => u.id === userId);

      if (!user || !user.googleRefreshToken) {
        return Response.json(
          { error: "User not found or no refresh token" },
          { status: 401 }
        );
      }

      oauth2Client.setCredentials({
        refresh_token: user.googleRefreshToken,
      });

      const { token: newGoogleAccessToken } = await oauth2Client.getAccessToken();
      if (!newGoogleAccessToken) {
        return Response.json(
          { error: "Failed to refresh Google token" },
          { status: 401 }
        );
      }

      // Optionally, you can get updated user info from Google here
      // For now, we'll just use the info from our DB
      userPayload = {
        id: user.id,
        email: user.email,
        name: user.name,
        picture: user.picture,
        provider: "google",
      };
    } else {
      // Existing logic for Apple or other providers
      userPayload = {
        id: userId,
        email: payload.email!,
        name: payload.name!,
        picture: payload.picture,
        provider: payload.provider,
      };
    }

    const secret = new TextEncoder().encode(JWT_SECRET);
    const newAccessToken = await new jose.SignJWT(userPayload)
      .setProtectedHeader({ alg: "HS256" })
      .setIssuedAt()
      .setExpirationTime(JWT_EXPIRATION_TIME)
      .sign(secret);

    const newRefreshToken = await new jose.SignJWT({
      id: userId,
      provider: provider,
    })
      .setProtectedHeader({ alg: "HS256" })
      .setIssuedAt()
      .setExpirationTime("30d")
      .sign(secret);

    if (platform === "web") {
      const sessionCookie = serialize(COOKIE_NAME, newAccessToken, { ...COOKIE_OPTIONS, sameSite: "lax" });
      const refreshCookie = serialize(
        REFRESH_COOKIE_NAME,
        newRefreshToken,
        { ...REFRESH_COOKIE_OPTIONS, sameSite: "lax" }
      );

      const headers = new Headers();
      headers.append("Set-Cookie", sessionCookie);
      headers.append("Set-Cookie", refreshCookie);
      return Response.json({ success: true }, { headers });
    } else {
      return Response.json({
        accessToken: newAccessToken,
        refreshToken: newRefreshToken,
      });
    }
  } catch (error) {
    console.error("Error refreshing token:", error);
    if (error instanceof jose.errors.JWTExpired) {
      return Response.json(
        { error: "Refresh token expired, please sign in again" },
        { status: 401 }
      );
    }
    return Response.json(
      { error: "Invalid refresh token, please sign in again" },
      { status: 401 }
    );
  }
}
