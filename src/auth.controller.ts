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
import {
  signUp,
  signIn,
  signOut,
  getSessionUser,
  confirmEmail,
  resendConfirmation,
  forgotPassword,
  changePassword,
  getRolesByEmail,
  selfAssignRole,
  SelfAssignableRole,
} from "./auth";

@Controller()
export class AuthController {
  // ── Auth: Sign In ─────────────────────────────────────────────────────────
  @Post("signin")
  @HttpCode(HttpStatus.OK)
  async signIn(@Body() body: any, @Res({ passthrough: true }) res: Response) {
    const { email, password } = body;
    if (!email || !password) {
      throw new BadRequestException("email và password là bắt buộc");
    }
    const { cookies, user } = await signIn(email, password);
    res.setHeader("Set-Cookie", cookies);
    return { message: "Đăng nhập thành công", user };
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

    const { cookies, user, message } = await signUp(
      email,
      password,
      full_name,
      age,
      job_field,
    );
    if (cookies.length > 0) res.setHeader("Set-Cookie", cookies);
    return { message, user };
  }

  // ── Auth: Sign Out ────────────────────────────────────────────────────────
  @Post("auth/signout")
  @HttpCode(HttpStatus.OK)
  async signOut(@Res({ passthrough: true }) res: Response) {
    const clearCookies = await signOut();
    res.setHeader("Set-Cookie", clearCookies);
    return { message: "Đã đăng xuất" };
  }

  // ── Auth: Forgot Password ─────────────────────────────────────────────────
  @Post("auth/forgot-password")
  @HttpCode(HttpStatus.OK)
  async forgotPassword(@Body() body: any) {
    const { email } = body;
    if (!email) throw new BadRequestException("email là bắt buộc");

    const { message } = await forgotPassword(email);
    return { message };
  }

  // ── Auth: Change Password (requires login) ────────────────────────────────
  @Post("auth/change-password")
  @HttpCode(HttpStatus.OK)
  async changePassword(@Req() req: Request, @Body() body: any) {
    const token = req.cookies["access_token"];
    if (!token) throw new UnauthorizedException("Chưa đăng nhập");

    const currentUser = await getSessionUser(token);
    if (!currentUser)
      throw new UnauthorizedException("Phiên đăng nhập không hợp lệ");

    const { old_password, new_password } = body;
    if (!old_password || !new_password) {
      throw new BadRequestException("old_password và new_password là bắt buộc");
    }

    const { message } = await changePassword(
      currentUser.email,
      old_password,
      new_password,
    );
    return { message };
  }

  // ── Auth: Confirm Email ───────────────────────────────────────────────────
  @Get("auth/confirm")
  @HttpCode(HttpStatus.OK)
  async confirmEmail(
    @Query("token_hash") token_hash: string,
    @Query("type") type: string,
    @Res({ passthrough: true }) res: Response,
  ) {
    if (!token_hash || !type) {
      throw new BadRequestException("Thiếu token_hash hoặc type");
    }

    const { cookies, user, message } = await confirmEmail(token_hash, type);
    res.setHeader("Set-Cookie", cookies);
    return { message, user };
  }

  // ── Auth: Resend Confirmation Email ───────────────────────────────────────
  @Post("auth/resend")
  @HttpCode(HttpStatus.OK)
  async resendConfirmation(@Body() body: any) {
    const { email } = body;
    if (!email) throw new BadRequestException("email là bắt buộc");

    const result = await resendConfirmation(email);
    return result;
  }

  // ── Session: Get current user ─────────────────────────────────────────────
  @Get("me")
  @HttpCode(HttpStatus.OK)
  async getMe(@Req() req: Request) {
    const token = req.cookies["access_token"];
    if (!token) throw new UnauthorizedException("Chưa đăng nhập");

    const user = await getSessionUser(token);
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

    const result = await selfAssignRole(token, role as SelfAssignableRole);
    return result;
  }

  // ── Admin: Lấy role của user theo email ─────────────────────────────────
  @Get("admin/roles")
  @HttpCode(HttpStatus.OK)
  async getRoles(@Req() req: Request, @Query("email") email: string) {
    const token = req.cookies["access_token"];
    if (!token) throw new UnauthorizedException("Chưa đăng nhập");

    if (!email) throw new BadRequestException("Thiếu query ?email=");

    const roles = await getRolesByEmail(email);
    return { email, roles };
  }
}
