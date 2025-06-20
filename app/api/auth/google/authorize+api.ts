import { GOOGLE_CLIENT_ID, GOOGLE_REDIRECT_URI } from "@/utils/constants";

export function GET(req: Request) {
  if (!GOOGLE_CLIENT_ID) {
    return Response.json(
      { error: "Google Client ID is not configured" },
      { status: 500 }
    );
  }

  const { searchParams } = new URL(req.url);
  const state = searchParams.get("state");
  const codeChallenge = searchParams.get("code_challenge");

  if (!state || !codeChallenge) {
    return Response.json(
      { error: "Missing state or code_challenge" },
      { status: 400 }
    );
  }

  const authUrl = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  authUrl.searchParams.set("client_id", GOOGLE_CLIENT_ID);
  authUrl.searchParams.set("redirect_uri", GOOGLE_REDIRECT_URI);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("scope", "openid email profile");
  authUrl.searchParams.set("code_challenge", codeChallenge);
  authUrl.searchParams.set("code_challenge_method", "S256");
  authUrl.searchParams.set("state", state);
  authUrl.searchParams.set("access_type", "offline"); // Required to get a refresh token
  authUrl.searchParams.set("prompt", "consent"); // Force prompt for refresh token

  return Response.redirect(authUrl.toString());
} 