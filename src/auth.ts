import { supabase } from "./db";
import { SafeUser } from "./User";

// ─── Helper: parse cookies from request header ────────────────────────────────
export function parseCookies(
  cookieHeader: string | undefined,
): Record<string, string> {
  if (!cookieHeader) return {};
  return Object.fromEntries(
    cookieHeader.split("; ").map((c) => {
      const [k, ...v] = c.split("=");
      return [k.trim(), v.join("=")];
    }),
  );
}

// ─── Helper: build Set-Cookie strings ────────────────────────────────────────
function buildCookies(
  accessToken: string,
  refreshToken: string,
  expiresIn: number,
  rememberMe: boolean = false,
): string[] {
  const isProduction = process.env.NODE_ENV === "production";
  const secure = isProduction ? "; Secure" : "";

  // rememberMe = true  → cookie tồn tại 30 ngày (persistent cookie)
  // rememberMe = false → session cookie (hết khi đóng trình duyệt)
  const accessMaxAge = rememberMe ? `; Max-Age=${expiresIn}` : "";
  const refreshMaxAge = rememberMe ? "; Max-Age=2592000" : ""; // 30 ngày

  return [
    `access_token=${accessToken}; HttpOnly; Path=/; SameSite=Strict${accessMaxAge}${secure}`,
    `refresh_token=${refreshToken}; HttpOnly; Path=/; SameSite=Strict${refreshMaxAge}${secure}`,
  ];
}
// ─── Sign Up ──────────────────────────────────────────────────────────────────
export async function signUp(
  email: string,
  password: string,
  full_name: string,
  age: number,
  job_field: string | null,
): Promise<{ cookies: string[]; user: SafeUser | null; message: string }> {
  // Gửi full_name, age, job_field vào metadata → trigger DB sẽ tự insert vào bảng users
  const { data, error } = await supabase.auth.signUp({
    email,
    password,
    options: {
      data: { full_name, age, job_field },
      // URL mà Supabase sẽ redirect sau khi user click link xác nhận trong email
      emailRedirectTo: `${process.env.SITE_URL ?? "http://localhost:3000"}/auth/confirm`,
    },
  });
  if (error) throw new Error(`Đăng ký thất bại: ${error.message}`);

  const { session } = data;

  // Email confirmation BẬT → session = null, chờ user xác nhận email
  if (!session) {
    return {
      cookies: [],
      user: null,
      message: "Đăng ký thành công! Vui lòng kiểm tra email để xác nhận tài khoản.",
    };
  }

  // Email confirmation TẮT → đăng nhập ngay
  const cookies = buildCookies(
    session.access_token,
    session.refresh_token,
    session.expires_in,
  );

  const { password_hash, ...safeFields } = (await supabase
    .from("users")
    .select("*")
    .eq("email", email)
    .single()).data ?? {};

  const safeUser: SafeUser = {
    user_id: safeFields.user_id ?? data.user!.id,
    email: data.user!.email!,
    full_name,
    age,
    created_at: data.user!.created_at,
    job_field,
    avatar_url: null,
    roles: null,
  };

  return { cookies, user: safeUser, message: "Đăng ký thành công" };
}

// ─── Confirm Email (xác nhận email từ link) ───────────────────────────────────
export async function confirmEmail(
  token_hash: string,
  type: string,
): Promise<{ cookies: string[]; user: SafeUser | null; message: string }> {
  // Verify OTP token từ link email
  const { data, error } = await supabase.auth.verifyOtp({
    token_hash,
    type: type as any, // 'signup' | 'email'
  });
  if (error) throw new Error(`Xác nhận email thất bại: ${error.message}`);

  const { session } = data;
  if (!session) throw new Error("Không thể tạo phiên đăng nhập sau xác nhận");

  // Lấy profile từ bảng users (trigger đã tạo khi signUp)
  const { data: userRow } = await supabase
    .from("users")
    .select("*")
    .eq("email", data.user!.email!)
    .single();

  const cookies = buildCookies(
    session.access_token,
    session.refresh_token,
    session.expires_in,
  );

  if (!userRow) {
    return {
      cookies,
      user: null,
      message: "Email đã xác nhận nhưng chưa tìm thấy profile",
    };
  }

  const { password_hash, ...safeFields } = userRow;
  return {
    cookies,
    user: { ...safeFields, roles: null },
    message: "Email đã xác nhận thành công!",
  };
}

// ─── Resend Confirmation Email ────────────────────────────────────────────────
export async function resendConfirmation(
  email: string,
): Promise<{ message: string }> {
  const { error } = await supabase.auth.resend({
    type: "signup",
    email,
    options: {
      emailRedirectTo: `${process.env.SITE_URL ?? "http://localhost:3000"}/auth/confirm`,
    },
  });
  if (error) throw new Error(`Gửi lại email thất bại: ${error.message}`);
  return { message: "Đã gửi lại email xác nhận. Vui lòng kiểm tra hộp thư." };
}

// ─── Login ────────────────────────────────────────────────────────────────────
export async function signIn(
  email: string,
  password: string,
): Promise<{ cookies: string[]; user: SafeUser }> {
  // 1. Authenticate with Supabase Auth
  const { data, error } = await supabase.auth.signInWithPassword({
    email,
    password,
  });
  if (error) throw new Error(`Đăng nhập thất bại: ${error.message}`);

  const { session } = data;

  // 2. Fetch user profile from your "users" table
  const { data: userRow, error: userErr } = await supabase
    .from("users")
    .select("*")
    .eq("email", email)
    .single();
  if (userErr || !userRow)
    throw new Error("Không tìm thấy user trong hệ thống");

  // 3. Fetch roles via user_roles join
  //   const { data: roleRows, error: roleErr } = await supabase
  //     .from("user_roles")
  //     .select("roles(role_name)")
  //     .eq("user_id", userRow.user_id);
  //   if (roleErr) throw new Error("Không thể lấy vai trò người dùng");

  //   const roles: string[] = (roleRows ?? [])
  //     .map((r: any) => r.roles?.role_name ?? "")
  //     .filter(Boolean);

  // 4. Build safe user (no password_hash)
  const { password_hash, ...safeFields } = userRow;
  const safeUser: SafeUser = { ...safeFields };

  // 5. Build cookies
  const cookies = buildCookies(
    session.access_token,
    session.refresh_token,
    session.expires_in,
  );

  return { cookies, user: safeUser };
}

// ─── Logout ───────────────────────────────────────────────────────────────────
export async function signOut(): Promise<string[]> {
  const { error } = await supabase.auth.signOut();
  if (error) throw new Error(error.message);

  return [
    "access_token=; HttpOnly; Path=/; Max-Age=0; SameSite=Strict",
    "refresh_token=; HttpOnly; Path=/; Max-Age=0; SameSite=Strict",
  ];
}

// ─── Forgot Password (gửi email reset) ───────────────────────────────────────
export async function forgotPassword(
  email: string,
): Promise<{ message: string }> {
  const { error } = await supabase.auth.resetPasswordForEmail(email, {
    redirectTo: `${process.env.SITE_URL ?? "http://localhost:3000"}/auth/reset-password`,
  });
  if (error) throw new Error(`Gửi email reset thất bại: ${error.message}`);
  return { message: "Đã gửi email reset mật khẩu. Vui lòng kiểm tra hộp thư." };
}

// ─── Reset Password (từ link email — KHÔNG cần mật khẩu cũ) ──────────────────
// User đã chứng minh danh tính qua email → chỉ cần access_token từ link + new_password
export async function resetPassword(
  access_token: string,
  refresh_token: string,
  new_password: string,
): Promise<{ message: string }> {
  // Set session từ token trong link reset email
  const { error: sessionErr } = await supabase.auth.setSession({
    access_token,
    refresh_token,
  });
  if (sessionErr) throw new Error(`Phiên không hợp lệ: ${sessionErr.message}`);

  const { error } = await supabase.auth.updateUser({
    password: new_password,
  });
  if (error) throw new Error(`Reset mật khẩu thất bại: ${error.message}`);
  return { message: "Đã reset mật khẩu thành công!" };
}

// ─── Change Password (đang đăng nhập — CẦN xác minh mật khẩu cũ) ────────────
// User muốn đổi mật khẩu trong lúc đang login → phải nhập đúng mật khẩu cũ
export async function changePassword(
  email: string,
  old_password: string,
  new_password: string,
): Promise<{ message: string }> {
  // Bước 1: Verify mật khẩu cũ bằng cách đăng nhập lại
  const { error: verifyErr } = await supabase.auth.signInWithPassword({
    email,
    password: old_password,
  });
  if (verifyErr) throw new Error("Mật khẩu cũ không đúng");

  // Bước 2: Đổi sang mật khẩu mới
  const { error } = await supabase.auth.updateUser({
    password: new_password,
  });
  if (error) throw new Error(`Đổi mật khẩu thất bại: ${error.message}`);
  return { message: "Đã đổi mật khẩu thành công!" };
}
// ─── Verify session from cookie ───────────────────────────────────────────────
export async function getSessionUser(
  accessToken: string,
): Promise<SafeUser | null> {
  const { data, error } = await supabase.auth.getUser(accessToken);
  if (error || !data.user?.email) return null;

  const { data: userRow } = await supabase
    .from("users")
    .select("*")
    .eq("email", data.user.email)
    .single();
  if (!userRow) return null;

  const { data: roleRows } = await supabase
    .from("user_roles")
    .select("roles(role_name)")
    .eq("user_id", userRow.user_id);

  const roles: string[] = (roleRows ?? [])
    .map((r: any) => r.roles?.role_name ?? "")
    .filter(Boolean);

  const { password_hash, ...safeFields } = userRow;
  return { ...safeFields, roles };
}
