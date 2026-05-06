import { supabase } from "./db/db";
import { SafeUser } from "./db/User";

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
      message:
        "Đăng ký thành công! Vui lòng kiểm tra email để xác nhận tài khoản.",
    };
  }

  // Email confirmation TẮT → đăng nhập ngay
  const cookies = buildCookies(
    session.access_token,
    session.refresh_token,
    session.expires_in,
  );

  const { password_hash, ...safeFields } =
    (await supabase.from("users").select("*").eq("email", email).single())
      .data ?? {};

  const safeUser: SafeUser = {
    user_id: data.user!.id,
    id: safeFields.id,
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

// ─── Các role user được phép tự đăng ký ──────────────────────────────────────
// Chỉ 'A' (Advertiser) và 'B' (Publisher) — KHÔNG cho phép tự gán 'admin'
const SELF_ASSIGNABLE_ROLES = ["A", "B"] as const;
export type SelfAssignableRole = (typeof SELF_ASSIGNABLE_ROLES)[number];

// ─── Tự đăng ký role A hoặc B (không cần admin) ──────────────────────────────
export async function selfAssignRole(
  accessToken: string,
  roleName: SelfAssignableRole,
): Promise<{ message: string; roles: string[] }> {
  // 1. Validate: chỉ cho phép A hoặc B
  if (!SELF_ASSIGNABLE_ROLES.includes(roleName))
    throw new Error(
      `Chỉ được đăng ký role 'A' (Advertiser) hoặc 'B' (Publisher)`,
    );

  // 2. Xác minh user từ token
  const user = await getSessionUser(accessToken);
  if (!user) throw new Error("Token không hợp lệ hoặc đã hết hạn");

  // 3. Tìm role_id từ role_name
  const { data: roleRow, error: roleErr } = await supabase
    .from("roles")
    .select("role_id")
    .eq("role_name", roleName)
    .single();

  if (roleErr || !roleRow)
    throw new Error(
      `Role '${roleName}' chưa được tạo trong DB. Chạy SQL seed trước.`,
    );

  // 4. Gán role (upsert — không lỗi nếu đã có)
  const { error: insertErr } = await supabase
    .from("user_roles")
    .upsert(
      { user_id: user.user_id, role_id: roleRow.role_id },
      { onConflict: "user_id,role_id" },
    );

  if (insertErr) throw new Error(`Đăng ký role thất bại: ${insertErr.message}`);

  // 5. Trả về danh sách role hiện tại
  const updatedRoles = await getRolesByEmail(user.email);
  return {
    message: `Đã đăng ký role '${roleName}' thành công`,
    roles: updatedRoles,
  };
}

// ─── Lấy roles của user theo email ───────────────────────────────────────────
export async function getRolesByEmail(email: string): Promise<string[]> {
  // 1. Tìm user_id từ email
  const { data: userRow, error: userErr } = await supabase
    .from("users")
    .select("user_id")
    .eq("email", email)
    .single();

  if (userErr || !userRow) throw new Error("Không tìm thấy user");

  // 2. Lấy danh sách roles qua bảng user_roles (join roles)
  const { data: roleRows, error: roleErr } = await supabase
    .from("user_roles")
    .select("roles(role_name)")
    .eq("user_id", userRow.user_id);

  if (roleErr) throw new Error(`Lấy role thất bại: ${roleErr.message}`);

  return (roleRows ?? [])
    .map((r: any) => r.roles?.role_name ?? "")
    .filter(Boolean);
}

// ─── Gán role cho user (CHỈ admin mới được gọi) ──────────────────────────────
// adminToken: access_token của người thực hiện hành động (phải là admin)
// targetEmail: email của user cần gán role
// roleName: tên role cần gán ('user', 'marketer', 'admin', ...)
// export async function assignRole(
//   adminToken: string,
//   targetEmail: string,
//   roleName: string,
// ): Promise<{ message: string }> {
//   // 1. Xác minh người gọi là admin
//   const admin = await getSessionUser(adminToken);
//   if (!admin) throw new Error("Token không hợp lệ");

//   const isAdmin = (admin.roles ?? []).includes("admin");
//   if (!isAdmin) throw new Error("Không có quyền thực hiện thao tác này");

//   // 2. Tìm role_id từ role_name
//   const { data: roleRow, error: roleErr } = await supabase
//     .from("roles")
//     .select("role_id")
//     .eq("role_name", roleName)
//     .single();

//   if (roleErr || !roleRow)
//     throw new Error(`Role "${roleName}" không tồn tại trong hệ thống`);

//   // 3. Tìm user_id của target
//   const { data: targetUser, error: targetErr } = await supabase
//     .from("users")
//     .select("user_id")
//     .eq("email", targetEmail)
//     .single();

//   if (targetErr || !targetUser)
//     throw new Error(`Không tìm thấy user với email: ${targetEmail}`);

//   // 4. Gán role (ON CONFLICT DO NOTHING — tránh duplicate)
//   const { error: insertErr } = await supabase.from("user_roles").upsert(
//     { user_id: targetUser.user_id, role_id: roleRow.role_id },
//     { onConflict: "user_id,role_id" },
//   );

//   if (insertErr) throw new Error(`Gán role thất bại: ${insertErr.message}`);

//   return { message: `Đã gán role "${roleName}" cho ${targetEmail}` };
// }

// // ─── Thu hồi role của user (CHỈ admin mới được gọi) ─────────────────────────
// export async function revokeRole(
//   adminToken: string,
//   targetEmail: string,
//   roleName: string,
// ): Promise<{ message: string }> {
//   // 1. Xác minh admin
//   const admin = await getSessionUser(adminToken);
//   if (!admin) throw new Error("Token không hợp lệ");
//   if (!(admin.roles ?? []).includes("admin"))
//     throw new Error("Không có quyền thực hiện thao tác này");

//   // 2. Tìm role_id
//   const { data: roleRow } = await supabase
//     .from("roles")
//     .select("role_id")
//     .eq("role_name", roleName)
//     .single();

//   if (!roleRow)
//     throw new Error(`Role "${roleName}" không tồn tại`);

//   // 3. Tìm user_id
//   const { data: targetUser } = await supabase
//     .from("users")
//     .select("user_id")
//     .eq("email", targetEmail)
//     .single();

//   if (!targetUser)
//     throw new Error(`Không tìm thấy user: ${targetEmail}`);

//   // 4. Xoá role
//   const { error } = await supabase
//     .from("user_roles")
//     .delete()
//     .eq("user_id", targetUser.user_id)
//     .eq("role_id", roleRow.role_id);

//   if (error) throw new Error(`Thu hồi role thất bại: ${error.message}`);

//   return { message: `Đã thu hồi role "${roleName}" của ${targetEmail}` };
// }
