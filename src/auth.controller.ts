import {
  Controller,
  Post,
  Get,
  Body,
  Req,
  Res,
  HttpCode,
  HttpStatus,
  UnauthorizedException,
  BadRequestException,
  Query,
} from "@nestjs/common";
import { Request, Response } from "express";
import { supabase } from "./db/db";
import { SafeUser } from "./db/User";

const SELF_ASSIGNABLE_ROLES = ["A", "B"] as const;
type SelfAssignableRole = (typeof SELF_ASSIGNABLE_ROLES)[number];

@Controller()
export class AuthController {
  private buildCookies(
    accessToken: string,
    refreshToken: string,
    expiresIn: number,
    rememberMe: boolean = false,
  ): string[] {
    const isProduction = process.env.NODE_ENV === "production";
    const secure = isProduction ? "; Secure" : "";
    const accessMaxAge = rememberMe ? `; Max-Age=${expiresIn}` : "";
    const refreshMaxAge = rememberMe ? "; Max-Age=2592000" : ""; // 30 ngày
    return [
      `access_token=${accessToken}; HttpOnly; Path=/; SameSite=Strict${accessMaxAge}${secure}`,
      `refresh_token=${refreshToken}; HttpOnly; Path=/; SameSite=Strict${refreshMaxAge}${secure}`,
    ];
  }

  private async getSessionUser(accessToken: string): Promise<SafeUser | null> {
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

  // ── Auth: Sign In ─────────────────────────────────────────────────────────
  @Post("auth/signin")
  @HttpCode(HttpStatus.OK)
  async signIn(@Body() body: any, @Res({ passthrough: true }) res: Response) {
    const { email, password } = body;
    if (!email || !password) {
      throw new BadRequestException("email và password là bắt buộc");
    }

    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password,
    });
    if (error) throw new BadRequestException(`Đăng nhập thất bại: ${error.message}`);

    const { session } = data;

    const { data: userRow, error: userErr } = await supabase
      .from("users")
      .select("*")
      .eq("email", email)
      .single();

    if (userErr || !userRow)
      throw new BadRequestException("Không tìm thấy user trong hệ thống");

    const { password_hash, ...safeFields } = userRow;
    const user: SafeUser = { ...safeFields, roles: null };

    const cookies = this.buildCookies(
      session.access_token,
      session.refresh_token,
      session.expires_in,
    );

    res.setHeader("Set-Cookie", cookies);
    return { message: "Đăng nhập thành công", user, cookies };
  }

  // ── Auth: Sign Up ─────────────────────────────────────────────────────────
  @Post("auth/signup")
  @HttpCode(HttpStatus.OK)
  async signUp(@Body() body: any, @Res({ passthrough: true }) res: Response) {
    const { email, password, full_name, age, job_field } = body;
    if (!email || !password || !full_name || !age || !job_field) {
      throw new BadRequestException(
        "email, password, full_name, age và job_field là bắt buộc",
      );
    }

    const { data, error } = await supabase.auth.signUp({
      email,
      password,
      options: {
        data: { full_name, age, job_field },
        emailRedirectTo: `${process.env.SITE_URL ?? "http://localhost:3000"}/auth/confirm`,
      },
    });
    if (error) throw new BadRequestException(`Đăng ký thất bại: ${error.message}`);

    const { session } = data;

    if (!session) {
      return { message: "Đăng ký thành công! Vui lòng kiểm tra email để xác nhận tài khoản.", user: null };
    }

    const cookies = this.buildCookies(
      session.access_token,
      session.refresh_token,
      session.expires_in,
    );

    const { data: userRow } = await supabase.from("users").select("*").eq("email", email).single();
    const { password_hash, ...safeFields } = userRow ?? {};

    const user: SafeUser = {
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

    if (cookies.length > 0) res.setHeader("Set-Cookie", cookies);
    return { message: "Đăng ký thành công", user, cookies };
  }

  // ── Auth: Sign Out ────────────────────────────────────────────────────────
  @Post("auth/signout")
  @HttpCode(HttpStatus.OK)
  async signOut(@Res({ passthrough: true }) res: Response) {
    const { error } = await supabase.auth.signOut();
    if (error) throw new BadRequestException(error.message);

    const clearCookies = [
      "access_token=; HttpOnly; Path=/; Max-Age=0; SameSite=Strict",
      "refresh_token=; HttpOnly; Path=/; Max-Age=0; SameSite=Strict",
    ];
    res.setHeader("Set-Cookie", clearCookies);
    return { message: "Đã đăng xuất" };
  }

  // ── Auth: Forgot Password ─────────────────────────────────────────────────
  @Post("auth/forgot-password")
  @HttpCode(HttpStatus.OK)
  async forgotPassword(@Body() body: any) {
    const { email } = body;
    if (!email) throw new BadRequestException("email là bắt buộc");

    const { error } = await supabase.auth.resetPasswordForEmail(email, {
      redirectTo: `${process.env.SITE_URL ?? "http://localhost:3000"}/auth/reset-password`,
    });
    if (error) throw new BadRequestException(`Gửi email reset thất bại: ${error.message}`);

    return { message: "Đã gửi email reset mật khẩu. Vui lòng kiểm tra hộp thư." };
  }

  // ── Auth: Change Password (requires login) ────────────────────────────────
  @Post("auth/change-password")
  @HttpCode(HttpStatus.OK)
  async changePassword(@Req() req: Request, @Body() body: any) {
    const token = req.cookies["access_token"];
    if (!token) throw new UnauthorizedException("Chưa đăng nhập");

    const currentUser = await this.getSessionUser(token);
    if (!currentUser)
      throw new UnauthorizedException("Phiên đăng nhập không hợp lệ");

    const { old_password, new_password } = body;
    if (!old_password || !new_password) {
      throw new BadRequestException("old_password và new_password là bắt buộc");
    }

    const { error: verifyErr } = await supabase.auth.signInWithPassword({
      email: currentUser.email,
      password: old_password,
    });
    if (verifyErr) throw new BadRequestException("Mật khẩu cũ không đúng");

    const { error } = await supabase.auth.updateUser({
      password: new_password,
    });
    if (error) throw new BadRequestException(`Đổi mật khẩu thất bại: ${error.message}`);

    return { message: "Đã đổi mật khẩu thành công!" };
  }

  // ── Auth: Confirm Email ───────────────────────────────────────────────────
  @Get("auth/confirm")
  @HttpCode(HttpStatus.OK)
  async confirmEmail(
    @Query("code") code: string,
    @Res({ passthrough: true }) res: Response,
  ) {
    if (!code) {
      throw new BadRequestException("Thiếu mã code xác nhận từ Supabase");
    }

    const { data, error } = await supabase.auth.exchangeCodeForSession(code);
    if (error) throw new BadRequestException(`Xác nhận email thất bại: ${error.message}`);

    const { session } = data;
    if (!session) throw new BadRequestException("Không thể tạo phiên đăng nhập sau xác nhận");

    const { data: userRow } = await supabase
      .from("users")
      .select("*")
      .eq("email", data.user!.email!)
      .single();

    const cookies = this.buildCookies(
      session.access_token,
      session.refresh_token,
      session.expires_in,
    );
    res.setHeader("Set-Cookie", cookies);

    if (!userRow) {
      return { message: "Email đã xác nhận nhưng chưa tìm thấy profile", user: null };
    }

    const { password_hash, ...safeFields } = userRow;
    return { message: "Email đã xác nhận thành công!", user: { ...safeFields, roles: null } };
  }

  // ── Auth: Resend Confirmation Email ───────────────────────────────────────
  @Post("auth/resend")
  @HttpCode(HttpStatus.OK)
  async resendConfirmation(@Body() body: any) {
    const { email } = body;
    if (!email) throw new BadRequestException("email là bắt buộc");

    const { error } = await supabase.auth.resend({
      type: "signup",
      email,
      options: {
        emailRedirectTo: `${process.env.SITE_URL ?? "http://localhost:3000"}/auth/confirm`,
      },
    });
    if (error) throw new BadRequestException(`Gửi lại email thất bại: ${error.message}`);

    return { message: "Đã gửi lại email xác nhận. Vui lòng kiểm tra hộp thư." };
  }

  // ── Session: Get current user ─────────────────────────────────────────────
  @Get("me")
  @HttpCode(HttpStatus.OK)
  async getMe(@Req() req: Request) {
    const token = req.cookies["access_token"];
    if (!token) throw new UnauthorizedException("Chưa đăng nhập");

    const user = await this.getSessionUser(token);
    if (!user) throw new UnauthorizedException("Phiên đăng nhập không hợp lệ");
    return { user };
  }

  // ── Auth: Tự đăng ký role A hoặc B ────────────────────────────────────────
  @Post("auth/role")
  @HttpCode(HttpStatus.OK)
  async selfAssignRole(@Req() req: Request, @Body() body: any) {
    const token = req.cookies["access_token"];
    if (!token) throw new UnauthorizedException("Chưa đăng nhập");

    const { role } = body;
    if (!role) throw new BadRequestException("Thiếu trường 'role'");
    if (role !== "A" && role !== "B") {
      throw new BadRequestException(
        "Chỉ được chọn role 'A' (Advertiser) hoặc 'B' (Publisher)",
      );
    }

    const user = await this.getSessionUser(token);
    if (!user) throw new UnauthorizedException("Token không hợp lệ hoặc đã hết hạn");

    const { data: roleRow, error: roleErr } = await supabase
      .from("roles")
      .select("role_id")
      .eq("role_name", role)
      .single();

    if (roleErr || !roleRow)
      throw new BadRequestException(`Role '${role}' chưa được tạo trong DB. Chạy SQL seed trước.`);

    const { error: insertErr } = await supabase
      .from("user_roles")
      .upsert(
        { user_id: user.user_id, role_id: roleRow.role_id },
        { onConflict: "user_id,role_id" },
      );

    if (insertErr) throw new BadRequestException(`Đăng ký role thất bại: ${insertErr.message}`);

    const { data: roleRows } = await supabase
      .from("user_roles")
      .select("roles(role_name)")
      .eq("user_id", user.user_id);

    const updatedRoles = (roleRows ?? []).map((r: any) => r.roles?.role_name ?? "").filter(Boolean);

    return { message: `Đã đăng ký role '${role}' thành công`, roles: updatedRoles };
  }

  // ── Admin: Lấy role của user theo email ─────────────────────────────────
  @Get("admin/roles")
  @HttpCode(HttpStatus.OK)
  async getRoles(@Req() req: Request, @Query("email") email: string) {
    const token = req.cookies["access_token"];
    if (!token) throw new UnauthorizedException("Chưa đăng nhập");

    if (!email) throw new BadRequestException("Thiếu query ?email=");

    const { data: userRow, error: userErr } = await supabase
      .from("users")
      .select("user_id")
      .eq("email", email)
      .single();

    if (userErr || !userRow) throw new BadRequestException("Không tìm thấy user");

    const { data: roleRows, error: roleErr } = await supabase
      .from("user_roles")
      .select("roles(role_name)")
      .eq("user_id", userRow.user_id);

    if (roleErr) throw new BadRequestException(`Lấy role thất bại: ${roleErr.message}`);

    const roles = (roleRows ?? []).map((r: any) => r.roles?.role_name ?? "").filter(Boolean);

    return { email, roles };
  }
}
