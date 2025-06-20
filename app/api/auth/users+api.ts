import { promises as fs } from "fs";
import path from "path";
import { withAuth } from "@/utils/middleware";

export const GET = withAuth(async (req, user) => {
  try {
    //const dbPath = path.join(process.cwd(), "db.json");
    const dbPath= "E:/MobileApp/expo-oauth-example/db.json"
    const dbRaw = await fs.readFile(dbPath, "utf-8");
    const db = JSON.parse(dbRaw);
    return Response.json({ users: db.users });
  } catch (e) {
    return Response.json({ users: [], error: "Could not read users" }, { status: 500 });
  }
}); 