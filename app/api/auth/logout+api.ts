import {
  COOKIE_NAME,
  REFRESH_COOKIE_NAME,
  COOKIE_OPTIONS,
  REFRESH_COOKIE_OPTIONS,
  JWT_SECRET,
} from "@/utils/constants";
import { OAuth2Client } from "google-auth-library";
import fs from "fs/promises";
import path from "path";
import * as jose from "jose";
import { serialize } from "cookie";

const GOOGLE_CLIENT_ID = '99090385428-o7c34t5u6703o1paid6qtvfac0be7rd5.apps.googleusercontent.com';
const GOOGLE_CLIENT_SECRET = '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';

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

async function writeDb(data: any) {
  await fs.writeFile(dbPath, JSON.stringify(data, null, 2), "utf-8");
}

const oauth2Client = new OAuth2Client(
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET
);

export async function POST(request: Request) {
  if (!JWT_SECRET) {
    console.error("JWT_SECRET is not configured");
    return Response.json({ error: "Server misconfiguration" }, { status: 500 });
  }
  const cookieHeader = request.headers.get("cookie");
  let refreshToken: string | undefined;
  if (cookieHeader) {
    const cookies = cookieHeader.split(";").reduce((acc, cookie) => {
      const [key, value] = cookie.trim().split("=");
      acc[key.trim()] = value;
      return acc;
    }, {} as Record<string, string>);
    refreshToken = cookies[REFRESH_COOKIE_NAME];
  }

  if (refreshToken) {
    try {
      const decoded = await jose.jwtVerify(
        refreshToken,
        new TextEncoder().encode(JWT_SECRET)
      );
      const payload = decoded.payload as { id: string; provider: string };
      const userId = payload.id;
      const provider = payload.provider;

      if (provider === "google") {
        const db = await readDb();
        const user = db.users.find((u: any) => u.id === userId);
        if (user && user.googleRefreshToken) {
          try {
            await oauth2Client.revokeToken(user.googleRefreshToken);
            console.log("Google token revoked for user:", userId);
            // Remove the refresh token from the database
            user.googleRefreshToken = null;
            await writeDb(db);
          } catch (e) {
            console.error("Failed to revoke google token", e);
          }
        }
      }
    } catch (e) {
      console.error("Error decoding refresh token during logout", e);
    }
  }

  try {
    const sessionCookie = serialize(COOKIE_NAME, "", { ...COOKIE_OPTIONS, sameSite: "lax", maxAge: -1 });
    const refreshCookie = serialize(REFRESH_COOKIE_NAME, "", {
      ...REFRESH_COOKIE_OPTIONS,
      sameSite: "lax",
      maxAge: -1,
    });

    const headers = new Headers();
    headers.append("Set-Cookie", sessionCookie);
    headers.append("Set-Cookie", refreshCookie);

    return Response.json({ success: true }, { headers });
  } catch (error) {
    console.error("Logout error:", error);
    return Response.json({ error: "Server error" }, { status: 500 });
  }
}
