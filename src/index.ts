import http from "http";
import "dotenv/config";
import { signUp, signIn, signOut, getSessionUser, parseCookies, confirmEmail, resendConfirmation, forgotPassword, changePassword } from "./auth";

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
    if (method === "POST" && url === "/signin") {
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
    if (method === "POST" && url === "/auth/signout") {
      const clearCookies = await signOut();
      res.setHeader("Set-Cookie", clearCookies);
      return send(res, 200, { message: "Đã đăng xuất" });
    }

    //POST /signUp
    if (method === "POST" && url === "/auth/signup") {
      const { email, password, full_name, age, job_field } = await readBody<{
        email: string;
        password: string;
        full_name: string;
        age: number;
        job_field: string;
      }>(req);
      if (!email || !password || !full_name || !age || !job_field)
        return send(res, 400, {
          message: "email, password, full_name, age và job_field là bắt buộc",
        });

      const { cookies, user, message } = await signUp(email, password, full_name, age, job_field);
      if (cookies.length > 0) res.setHeader("Set-Cookie", cookies);
      return send(res, 200, { message, user });
    }
    // POST /auth/forgot-password — gửi email reset (không cần đăng nhập)
    if (method === "POST" && url === "/auth/forgot-password") {
      const { email } = await readBody<{
        email: string;
      }>(req);
      if (!email) return send(res, 400, { message: "email là bắt buộc" });

      const { message } = await forgotPassword(email);
      return send(res, 200, { message });
    }

    // POST /auth/change-password — đổi mật khẩu (CẦN đăng nhập)
    if (method === "POST" && url === "/auth/change-password") {
      // 1. Kiểm tra cookie — user phải đang đăng nhập
      const cookieData = parseCookies(req.headers.cookie);
      const token = cookieData["access_token"];
      if (!token) return send(res, 401, { message: "Chưa đăng nhập" });

      const currentUser = await getSessionUser(token);
      if (!currentUser) return send(res, 401, { message: "Phiên đăng nhập không hợp lệ" });

      // 2. Đọc body
      const { old_password, new_password } = await readBody<{
        old_password: string;
        new_password: string;
      }>(req);
      if (!old_password || !new_password)
        return send(res, 400, { message: "old_password và new_password là bắt buộc" });

      // 3. Đổi mật khẩu (email lấy từ session, không từ body → bảo mật hơn)
      const { message } = await changePassword(currentUser.email, old_password, new_password);
      return send(res, 200, { message });
    }

    // GET /auth/confirm — xác nhận email từ link
    if (method === "GET" && url?.startsWith("/auth/confirm")) {
      const parsedUrl = new URL(url, `http://localhost:${PORT}`);
      const token_hash = parsedUrl.searchParams.get("token_hash");
      const type = parsedUrl.searchParams.get("type");

      if (!token_hash || !type)
        return send(res, 400, { message: "Thiếu token_hash hoặc type" });

      const { cookies, user, message } = await confirmEmail(token_hash, type);
      res.setHeader("Set-Cookie", cookies);
      return send(res, 200, { message, user });
    }

    // POST /auth/resend — gửi lại email xác nhận
    if (method === "POST" && url === "/auth/resend") {
      const { email } = await readBody<{ email: string }>(req);
      if (!email)
        return send(res, 400, { message: "email là bắt buộc" });

      const result = await resendConfirmation(email);
      return send(res, 200, result);
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
