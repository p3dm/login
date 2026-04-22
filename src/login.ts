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
): string[] {
  const isProduction = process.env.NODE_ENV === "production";
  const secure = isProduction ? "; Secure" : "";
  return [
    `access_token=${accessToken}; HttpOnly; Path=/; Max-Age=${expiresIn}; SameSite=Strict${secure}`,
    `refresh_token=${refreshToken}; HttpOnly; Path=/; Max-Age=604800; SameSite=Strict${secure}`,
  ];
}
// ---signup---------------------------------------------------------------------
export async function signUp(
  email: string,
  password: string,
  full_name: string,
  age: number,
): Promise<{ cookies: string[]; user: SafeUser }> {
  // Kiểm tra email đã tồn tại chưa (không dùng .single() để tránh lỗi khi không tìm thấy)
  const { data: existingUsers, error: checkError } = await supabase
    .from("users")
    .select("*")
    .eq("email", email);

  if (checkError) throw new Error(`Lỗi kiểm tra email: ${checkError.message}`);
  if (existingUsers && existingUsers.length > 0)
    throw new Error("Email đã được sử dụng");

  const { data, error } = await supabase.auth.signUp({ email, password });
  if (error) throw new Error(`Đăng ký thất bại: ${error.message}`);

  const { session } = data;
  if (!session) throw new Error("Vui lòng xác nhận email trước khi đăng nhập");

  const { data: newUser, error: insertErr } = await supabase
    .from("users")
    .insert({ email, full_name, age })
    .select()
    .single<SafeUser>();
  if (insertErr || !newUser) throw new Error("Không thể tạo hồ sơ người dùng");

  const { password_hash, ...safeFields } = newUser as any;
  const safeUser: SafeUser = { ...safeFields };

  const cookies = buildCookies(
    session.access_token,
    session.refresh_token,
    session.expires_in,
  );

  return { cookies, user: safeUser };
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
