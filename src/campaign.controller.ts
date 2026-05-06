import {
  Controller,
  Post,
  Get,
  Patch,
  Delete,
  Body,
  Req,
  Param,
  HttpCode,
  HttpStatus,
  UnauthorizedException,
  BadRequestException,
} from "@nestjs/common";
import { Request } from "express";
import { getSessionUser } from "./auth";
import {
  createCampaign,
  getCampaignsByOwner,
  getActiveCampaigns,
  getCampaignById,
  updateCampaign,
  deleteCampaign,
  applyToCampaign,
  reviewApplication,
  getApplicationsByCampaign,
  getMyApplications,
} from "./createCampaign";

@Controller()
export class CampaignController {
  // ── Campaign: Tạo chiến dịch mới (CHỈ role A) ────────────────────────────
  @Post("campaigns")
  @HttpCode(HttpStatus.CREATED)
  async createCampaign(@Req() req: Request, @Body() body: any) {
    const token = req.cookies["access_token"];
    if (!token) throw new UnauthorizedException("Chưa đăng nhập");

    const user = await getSessionUser(token);
    if (!user) throw new UnauthorizedException("Phiên đăng nhập không hợp lệ");

    const campaign = await createCampaign(user.user_id, body);
    return { campaign };
  }

  // ── Campaign: Lấy danh sách chiến dịch của user hiện tại ─────────────────
  @Get("campaigns")
  @HttpCode(HttpStatus.OK)
  async getCampaigns(@Req() req: Request) {
    const token = req.cookies["access_token"];
    if (!token) throw new UnauthorizedException("Chưa đăng nhập");

    const user = await getSessionUser(token);
    if (!user) throw new UnauthorizedException("Phiên đăng nhập không hợp lệ");

    const campaigns = await getCampaignsByOwner(user.user_id);
    return { campaigns };
  }

  // ── Campaign: Role B xem danh sách campaign đang active ────────────────────
  @Get("campaigns/available")
  @HttpCode(HttpStatus.OK)
  async getAvailableCampaigns(@Req() req: Request) {
    const token = req.cookies["access_token"];
    if (!token) throw new UnauthorizedException("Chưa đăng nhập");

    const user = await getSessionUser(token);
    if (!user) throw new UnauthorizedException("Phiên đăng nhập không hợp lệ");

    const campaigns = await getActiveCampaigns(user.user_id);
    return { campaigns };
  }

  // ── Campaign: Lấy chi tiết 1 chiến dịch ──────────────────────────────────
  @Get("campaigns/:id")
  @HttpCode(HttpStatus.OK)
  async getCampaignById(@Req() req: Request, @Param("id") campaign_id: string) {
    const token = req.cookies["access_token"];
    if (!token) throw new UnauthorizedException("Chưa đăng nhập");

    const user = await getSessionUser(token);
    if (!user) throw new UnauthorizedException("Phiên đăng nhập không hợp lệ");

    const campaign = await getCampaignById(campaign_id);
    return { campaign };
  }

  // ── Campaign: Cập nhật chiến dịch ────────────────────────────────────────
  @Patch("campaigns/:id")
  @HttpCode(HttpStatus.OK)
  async updateCampaign(
    @Req() req: Request,
    @Param("id") campaign_id: string,
    @Body() body: any,
  ) {
    const token = req.cookies["access_token"];
    if (!token) throw new UnauthorizedException("Chưa đăng nhập");

    const user = await getSessionUser(token);
    if (!user) throw new UnauthorizedException("Phiên đăng nhập không hợp lệ");

    const campaign = await updateCampaign(campaign_id, user.user_id, body);
    return { campaign };
  }

  // ── Campaign: Xoá chiến dịch ─────────────────────────────────────────────
  @Delete("campaigns/:id")
  @HttpCode(HttpStatus.OK)
  async deleteCampaign(@Req() req: Request, @Param("id") campaign_id: string) {
    const token = req.cookies["access_token"];
    if (!token) throw new UnauthorizedException("Chưa đăng nhập");

    const user = await getSessionUser(token);
    if (!user) throw new UnauthorizedException("Phiên đăng nhập không hợp lệ");

    await deleteCampaign(campaign_id, user.user_id);
    return { message: "Đã xoá chiến dịch thành công" };
  }

  // ── Campaign: Role B đăng ký nhận campaign ──────────────────────────────
  @Post("campaigns/:id/apply")
  @HttpCode(HttpStatus.CREATED)
  async applyToCampaign(
    @Req() req: Request,
    @Param("id") campaign_id: string,
    @Body() body: any,
  ) {
    const token = req.cookies["access_token"];
    if (!token) throw new UnauthorizedException("Chưa đăng nhập");

    const user = await getSessionUser(token);
    if (!user) throw new UnauthorizedException("Phiên đăng nhập không hợp lệ");

    const application = await applyToCampaign(
      user.user_id,
      campaign_id,
      body?.note,
    );
    return { application };
  }

  // ── Campaign: Role A xem các đơn đăng ký của campaign ──────────────────────
  @Get("campaigns/:id/applications")
  @HttpCode(HttpStatus.OK)
  async getApplicationsByCampaign(
    @Req() req: Request,
    @Param("id") campaign_id: string,
  ) {
    const token = req.cookies["access_token"];
    if (!token) throw new UnauthorizedException("Chưa đăng nhập");

    const user = await getSessionUser(token);
    if (!user) throw new UnauthorizedException("Phiên đăng nhập không hợp lệ");

    const applications = await getApplicationsByCampaign(
      user.user_id,
      campaign_id,
    );
    return { applications };
  }

  // ── Campaign: Role A duyệt / từ chối đơn ────────────────────────────────
  @Patch("applications/:id")
  @HttpCode(HttpStatus.OK)
  async reviewApplication(
    @Req() req: Request,
    @Param("id") application_id: string,
    @Body() body: any,
  ) {
    const token = req.cookies["access_token"];
    if (!token) throw new UnauthorizedException("Chưa đăng nhập");

    const user = await getSessionUser(token);
    if (!user) throw new UnauthorizedException("Phiên đăng nhập không hợp lệ");

    const { decision } = body;
    if (decision !== "approved" && decision !== "rejected") {
      throw new BadRequestException(
        "decision phải là 'approved' hoặc 'rejected'",
      );
    }

    const application = await reviewApplication(
      user.user_id,
      application_id,
      decision,
    );
    return { application };
  }

  // ── Campaign: Role B xem các đơn mình đã đăng ký ──────────────────────────
  @Get("my-applications")
  @HttpCode(HttpStatus.OK)
  async getMyApplications(@Req() req: Request) {
    const token = req.cookies["access_token"];
    if (!token) throw new UnauthorizedException("Chưa đăng nhập");

    const user = await getSessionUser(token);
    if (!user) throw new UnauthorizedException("Phiên đăng nhập không hợp lệ");

    const applications = await getMyApplications(user.user_id);
    return { applications };
  }
}
