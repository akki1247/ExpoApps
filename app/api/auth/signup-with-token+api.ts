import * as jose from "jose";
import fs from "fs/promises";
import path from "path";
import { serialize } from "cookie";
import {
  JWT_SECRET,
  COOKIE_NAME,
  REFRESH_COOKIE_NAME,
  COOKIE_OPTIONS,
  REFRESH_COOKIE_OPTIONS,
  JWT_EXPIRATION_TIME,
  REFRESH_TOKEN_EXPIRY,
} from "@/utils/constants";
import { AuthUser, withCORS } from "@/utils/middleware"; // Assuming withCORS and AuthUser are available

// Database path (consistent with other files)
const dbPath = "E:/MobileApp/expo-oauth-example/db.json";

async function readDb() {
  try {
    const data = await fs.readFile(dbPath, "utf-8");
    return JSON.parse(data);
  } catch (error: any) {
    if (error.code === "ENOENT") {
      return { users: [] }; // Return a default structure if file doesn't exist
    }
    throw error;
  }
}

async function writeDb(data: any) {
  await fs.writeFile(dbPath, JSON.stringify(data, null, 2), "utf-8");
}

export const POST = withCORS(async function POST(req: Request) {
  if (!JWT_SECRET) {
    console.error("JWT_SECRET is not configured");
    return Response.json(
      { error: "Server misconfiguration" },
      { status: 500 }
    );
  }

  let requestBody;
  try {
    requestBody = await req.json();
  } catch (error) {
    return Response.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  const { googleAccessToken, platform = "native" } = requestBody;

  if (!googleAccessToken) {
    return Response.json(
      { error: "Missing googleAccessToken" },
      { status: 400 }
    );
  }

  try {
    // 1. Fetch user info from Google using the access token
    const getAuthoriseUrl = await fetch(
      "https://accounts.google.com/o/oauth2/v2/auth",
      {
        method: "GET",
        
      }
    );

    const googleResponse = await fetch(
      "https://www.googleapis.com/oauth2/v3/userinfo",
      {
        headers: {
          Authorization: `Bearer ${googleAccessToken}`,
        },
      }
    );

    if (!googleResponse.ok) {
      const errorData = await googleResponse.json();
      console.error("Failed to fetch user info from Google:", errorData);
      return Response.json(
        { error: "Failed to fetch user info from Google", details: errorData },
        { status: googleResponse.status }
      );
    }

    const googleUser = await googleResponse.json();

    if (!googleUser.sub || !googleUser.email) {
      return Response.json(
        { error: "Invalid user payload from Google (missing sub or email)" },
        { status: 500 }
      );
    }

    // 2. Read DB and check if user exists
    const db = await readDb();
    let user = db.users.find((u: any) => u.id === googleUser.sub);

    if (user) {
      return Response.json({ error: "User already exists" }, { status: 409 }); // 409 Conflict
    }

    // 3. Create new user
    const newUser = {
      id: googleUser.sub, // Google's unique user ID
      email: googleUser.email,
      name: googleUser.name || "",
      picture: googleUser.picture || "",
      provider: "google",
      // Note: googleRefreshToken is not available in this flow
      // It's obtained during the authorization code exchange.
    };
    db.users.push(newUser);
    await writeDb(db);

    // 4. Prepare user payload for our application's JWT
    const appUserPayload: AuthUser = {
      id: newUser.id,
      email: newUser.email,
      name: newUser.name,
      picture: newUser.picture,
      provider: "google",
    };

    const secret = new TextEncoder().encode(JWT_SECRET);
    const appAccessToken = await new jose.SignJWT(appUserPayload)
      .setProtectedHeader({ alg: "HS256" })
      .setIssuedAt()
      .setExpirationTime(JWT_EXPIRATION_TIME) // e.g., "15m"
      .sign(secret);

    const appRefreshToken = await new jose.SignJWT({ id: newUser.id, provider: "google" })
      .setProtectedHeader({ alg: "HS256" })
      .setIssuedAt()
      .setExpirationTime(REFRESH_TOKEN_EXPIRY) // e.g., "30d"
      .sign(secret);

    // 5. Return tokens
    if (platform === "web") {
      const sessionCookie = serialize(COOKIE_NAME, appAccessToken, { ...COOKIE_OPTIONS, sameSite: "lax" });
      const refreshCookieVal = serialize(REFRESH_COOKIE_NAME, appRefreshToken, { ...REFRESH_COOKIE_OPTIONS, sameSite: "lax" });

      const headers = new Headers();
      headers.append("Set-Cookie", sessionCookie);
      headers.append("Set-Cookie", refreshCookieVal);

      return Response.json({ success: true, user: appUserPayload }, { headers });
    } else {
      // For native, return tokens in the body
      return Response.json({
        accessToken: appAccessToken,
        refreshToken: appRefreshToken,
        user: appUserPayload,
      });
    }
  } catch (error) {
    console.error("Error during signup with token:", error);
    return Response.json(
      { error: "Failed to sign up user" },
      { status: 500 }
    );
  }
});