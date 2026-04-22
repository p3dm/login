import http from "http";
import "dotenv/config";
import { signUp, signIn, signOut, getSessionUser, parseCookies } from "./login";

const PORT = process.env.PORT || 3000;

// ─── Helper: read request body as JSON ───────────────────────────────────────
async function readBody<T>(req: http.IncomingMessage): Promise<T> {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => {
      try {
        resolve(JSON.parse(body));
      } catch {
        reject(new Error("Invalid JSON body"));
      }
    });
  });
}

// ─── Helper: send JSON response ───────────────────────────────────────────────
function send(res: http.ServerResponse, status: number, body: object) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
}

// ─── Server ───────────────────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  const { method, url } = req;

  try {
    // POST /login
    if (method === "POST" && url === "/login") {
      const { email, password } = await readBody<{
        email: string;
        password: string;
      }>(req);
      if (!email || !password)
        return send(res, 400, { message: "email và password là bắt buộc" });

      const { cookies, user } = await signIn(email, password);
      res.setHeader("Set-Cookie", cookies);
      return send(res, 200, { message: "Đăng nhập thành công", user });
    }

    // POST /logout
    if (method === "POST" && url === "/logout") {
      const clearCookies = await signOut();
      res.setHeader("Set-Cookie", clearCookies);
      return send(res, 200, { message: "Đã đăng xuất" });
    }

    //POST /signUp
    if (method === "POST" && url === "/signUp") {
      const { email, password, full_name, age } = await readBody<{
        email: string;
        password: string;
        full_name: string;
        age: number;
      }>(req);
      if (!email || !password || !full_name || !age)
        return send(res, 400, {
          message: "email, password, full_name và age là bắt buộc",
        });

      const { cookies, user } = await signUp(email, password, full_name, age);
      res.setHeader("Set-Cookie", cookies);
      return send(res, 200, { message: "Đăng ký thành công", user });
    }

    // GET /me  — verify session from cookie
    if (method === "GET" && url === "/me") {
      const cookies = parseCookies(req.headers.cookie);
      const token = cookies["access_token"];
      if (!token) return send(res, 401, { message: "Chưa đăng nhập" });

      const user = await getSessionUser(token);
      if (!user)
        return send(res, 401, { message: "Phiên đăng nhập không hợp lệ" });
      return send(res, 200, { user });
    }

    // GET /  — health check
    if (method === "GET" && url === "/") {
      return send(res, 200, {
        message: "🚀 Authorize server is running!",
        status: "ok",
      });
    }

    send(res, 404, { message: "Route không tồn tại" });
  } catch (err: any) {
    console.error("❌ Error:", err.message);
    send(res, 500, { message: err.message ?? "Lỗi server" });
  }
});

server.listen(PORT, () => {
  console.log(`🚀 Server đang chạy tại http://localhost:${PORT}`);
});
