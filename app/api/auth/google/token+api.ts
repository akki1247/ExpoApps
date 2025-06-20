import { OAuth2Client } from "google-auth-library";
import * as jose from "jose";
import fs from "fs/promises";
import path from "path";
import { AuthUser, withCORS } from "@/utils/middleware";
import { COOKIE_NAME, JWT_SECRET, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI } from "@/utils/constants";
import { serialize } from "cookie";

console.log(">> cookieName", COOKIE_NAME);
console.log(">> googleClientId", GOOGLE_CLIENT_ID);
console.log(">> googleClientSecret", GOOGLE_CLIENT_SECRET);
console.log(">> googleRedirectUri", GOOGLE_REDIRECT_URI);
console.log(">> jwtSecret", JWT_SECRET);

// Simple in-memory database simulation (replace with a real database in production)
// This is used to store user information and refresh tokens

//const dbPath = path.resolve(process.cwd(), "db.json");
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

const oauth2Client = new OAuth2Client(
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  GOOGLE_REDIRECT_URI
);

export const POST = withCORS(async function POST(req: Request) {
  if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET || !JWT_SECRET) {
    console.error("Missing required environment variables for Google Auth");
    return Response.json(
      { error: "Server misconfiguration" },
      { status: 500 }
    );
  }

  const formData = await req.formData();
  const code = formData.get("code") as string;
  const platform = formData.get("platform") as string;
  const codeVerifier = formData.get("code_verifier") as string | null;
  const mode = (formData.get("mode") as string) || "login";

  if (!code) {
    return Response.json({ error: "Missing code" }, { status: 400 });
  }

  try {
    // Exchange code for tokens
    const tokenRequest: any = {
      code,
      client_id: GOOGLE_CLIENT_ID,
      client_secret: GOOGLE_CLIENT_SECRET,
      redirect_uri: GOOGLE_REDIRECT_URI,
      grant_type: "authorization_code",
    };
    if (codeVerifier && codeVerifier !== "null") {
      tokenRequest.code_verifier = codeVerifier;
    }
    const { tokens } = await oauth2Client.getToken(tokenRequest);

    if (!tokens.id_token) {
      return Response.json(
        { error: "Missing id_token from Google" },
        { status: 500 }
      );
    }

    // Get user info from Google
    const ticket = await oauth2Client.verifyIdToken({
      idToken: tokens.id_token,
      audience: GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    if (!payload || !payload.sub || !payload.email) {
      return Response.json(
        { error: "Invalid user payload from Google" },
        { status: 500 }
      );
    }

    // Read DB
    const db = await readDb();
    let user = db.users.find((u: any) => u.id === payload.sub);

    if (mode === "signup") {
      if (user) {
        return Response.json({ error: "User already exists" }, { status: 400 });
      }
      // Insert new user from Google data
      user = {
        id: payload.sub,
        email: payload.email,
        name: payload.name,
        picture: payload.picture,
        provider: "google",
        googleRefreshToken: tokens.refresh_token,
      };
      db.users.push(user);
      await writeDb(db);
    } else if (mode === "login") {
      if (!user) {
        return Response.json({ error: "User not found, please sign up first" }, { status: 400 });
      }
      // Optionally update refresh token if present (token rotation)
      if (tokens.refresh_token) {
        user.googleRefreshToken = tokens.refresh_token;
        await writeDb(db);
      }
    }

    // Prepare user payload for JWT
    const userPayload: AuthUser = {
      id: user.id,
      email: user.email,
      name: user.name!,
      picture: user.picture,
      provider: "google",
    };

    const secret = new TextEncoder().encode(JWT_SECRET);
    const accessToken = await new jose.SignJWT(userPayload)
      .setProtectedHeader({ alg: "HS256" })
      .setIssuedAt()
      .setExpirationTime("15m")
      .sign(secret);

    const refreshToken = await new jose.SignJWT({ id: user.id })
      .setProtectedHeader({ alg: "HS256" })
      .setIssuedAt()
      .setExpirationTime("30d")
      .sign(secret);

    if (platform === "web") {
      const cookieExpiration = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days
      const sessionCookie = serialize(COOKIE_NAME, accessToken, {
        httpOnly: true,
        secure: false,
        path: "/",
        sameSite: "lax",
        expires: new Date(Date.now() + 15 * 60 * 1000), // 15 minutes
      });
      const refreshCookie = serialize("refreshToken", refreshToken, {
        httpOnly: true,
        secure: false,
        path: "/",
        sameSite: "lax",
        expires: cookieExpiration,
      });

      const headers = new Headers();
      headers.append("Set-Cookie", sessionCookie);
      headers.append("Set-Cookie", refreshCookie);

      return Response.json({ success: true }, { headers });
    } else {
      // For native, return tokens in the body
      return Response.json({ accessToken, refreshToken });
    }
  } catch (error) {
    console.error("Error exchanging code for token:", error);
    return Response.json(
      { error: "Failed to authenticate with Google" },
      { status: 500 }
    );
  }
}); 