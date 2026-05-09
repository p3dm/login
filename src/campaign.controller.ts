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
import { supabase } from "./db/db";
import { SafeUser } from "./db/User";
import { Campaign, CampaignTarget, CampaignMetric, CampaignFull, CampaignApplication } from "./db/Campaign";

@Controller()
export class CampaignController {

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

  private async hasRole(user_id: string, roleName: string): Promise<boolean> {
    const { data } = await supabase
      .from("user_roles")
      .select("roles(role_name)")
      .eq("user_id", user_id);

    return (data ?? []).some((r: any) => r.roles?.role_name === roleName);
  }

  // ── Campaign: Tạo chiến dịch mới (CHỈ role A) ────────────────────────────
  @Post("campaigns")
  @HttpCode(HttpStatus.CREATED)
  async createCampaign(@Req() req: Request, @Body() body: any) {
    const token = req.cookies["access_token"];
    if (!token) throw new UnauthorizedException("Chưa đăng nhập");

    const user = await this.getSessionUser(token);
    if (!user) throw new UnauthorizedException("Phiên đăng nhập không hợp lệ");

    const isAdvertiser = await this.hasRole(user.user_id, "A");
    if (!isAdvertiser)
      throw new BadRequestException("Chỉ Advertiser (role A) mới được tạo chiến dịch. Hãy đăng ký role A trước.");

    const { name, description, budget, target } = body;

    if (!name || name.trim() === "")
      throw new BadRequestException("Tên chiến dịch không được để trống");

    if (budget !== undefined && (isNaN(budget) || budget < 0))
      throw new BadRequestException("Ngân sách phải là số không âm");

    const { data: campaign, error: campaignErr } = await supabase
      .from("campaigns")
      .insert({
        owner_id: user.user_id,
        name: name.trim(),
        description: description ?? null,
        budget: budget ?? null,
        status: "draft",
      })
      .select()
      .single();

    if (campaignErr || !campaign)
      throw new BadRequestException(`Tạo chiến dịch thất bại: ${campaignErr?.message}`);

    let targets: any[] = [];
    if (target) {
      const { data: targetRow, error: targetErr } = await supabase
        .from("campaign_targets")
        .insert({
          campaign_id: campaign.campaign_id,
          job_fields: target.job_fields ?? null,
          regions: target.regions ?? null,
        })
        .select()
        .single();

      if (targetErr) throw new BadRequestException(`Tạo target thất bại: ${targetErr.message}`);
      targets = [targetRow];
    }

    return { campaign: { ...(campaign as Campaign), targets, metrics: [] } };
  }

  // ── Campaign: Lấy danh sách chiến dịch của user hiện tại ─────────────────
  @Get("campaigns")
  @HttpCode(HttpStatus.OK)
  async getCampaigns(@Req() req: Request) {
    const token = req.cookies["access_token"];
    if (!token) throw new UnauthorizedException("Chưa đăng nhập");

    const user = await this.getSessionUser(token);
    if (!user) throw new UnauthorizedException("Phiên đăng nhập không hợp lệ");

    const { data, error } = await supabase
      .from("campaigns")
      .select("*")
      .eq("owner_id", user.user_id)
      .order("created_at", { ascending: false });

    if (error) throw new BadRequestException(`Lấy danh sách chiến dịch thất bại: ${error.message}`);
    return { campaigns: data ?? [] };
  }

  // ── Campaign: Role B xem danh sách campaign đang active ────────────────────
  @Get("campaigns/available")
  @HttpCode(HttpStatus.OK)
  async getAvailableCampaigns(@Req() req: Request) {
    const token = req.cookies["access_token"];
    if (!token) throw new UnauthorizedException("Chưa đăng nhập");

    const user = await this.getSessionUser(token);
    if (!user) throw new UnauthorizedException("Phiên đăng nhập không hợp lệ");

    const { data, error } = await supabase
      .from("campaigns")
      .select("*")
      .eq("status", "ACTIVE")
      .order("created_at", { ascending: false });

    if (error) throw new BadRequestException(`Lấy danh sách chiến dịch thất bại: ${error.message}`);
    return { campaigns: data ?? [] };
  }

  // ── Campaign: Lấy chi tiết 1 chiến dịch ──────────────────────────────────
  @Get("campaigns/:id")
  @HttpCode(HttpStatus.OK)
  async getCampaignById(@Req() req: Request, @Param("id") campaign_id: string) {
    const token = req.cookies["access_token"];
    if (!token) throw new UnauthorizedException("Chưa đăng nhập");

    const user = await this.getSessionUser(token);
    if (!user) throw new UnauthorizedException("Phiên đăng nhập không hợp lệ");

    const { data: campaign, error: campaignErr } = await supabase
      .from("campaigns")
      .select("*")
      .eq("campaign_id", campaign_id)
      .single();

    if (campaignErr || !campaign) throw new BadRequestException("Không tìm thấy chiến dịch");

    const { data: targets } = await supabase
      .from("campaign_targets")
      .select("*")
      .eq("campaign_id", campaign_id);

    const { data: metrics } = await supabase
      .from("campaign_metrics")
      .select("*")
      .eq("campaign_id", campaign_id)
      .order("recorded_at", { ascending: false })
      .limit(10);

    return {
      campaign: {
        ...(campaign as Campaign),
        targets: targets ?? [],
        metrics: metrics ?? [],
      }
    };
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

    const user = await this.getSessionUser(token);
    if (!user) throw new UnauthorizedException("Phiên đăng nhập không hợp lệ");

    if (body.start_date && body.end_date) {
      if (new Date(body.end_date) < new Date(body.start_date))
        throw new BadRequestException("Ngày kết thúc phải sau ngày bắt đầu");
    }

    const { data, error } = await supabase
      .from("campaigns")
      .update({ ...body, updated_at: new Date().toISOString() })
      .eq("campaign_id", campaign_id)
      .eq("owner_id", user.user_id)
      .select()
      .single();

    if (error || !data)
      throw new BadRequestException(`Cập nhật chiến dịch thất bại: ${error?.message}`);

    return { campaign: data };
  }

  // ── Campaign: Xoá chiến dịch ─────────────────────────────────────────────
  @Delete("campaigns/:id")
  @HttpCode(HttpStatus.OK)
  async deleteCampaign(@Req() req: Request, @Param("id") campaign_id: string) {
    const token = req.cookies["access_token"];
    if (!token) throw new UnauthorizedException("Chưa đăng nhập");

    const user = await this.getSessionUser(token);
    if (!user) throw new UnauthorizedException("Phiên đăng nhập không hợp lệ");

    const { error } = await supabase
      .from("campaigns")
      .delete()
      .eq("campaign_id", campaign_id)
      .eq("owner_id", user.user_id);

    if (error) throw new BadRequestException(`Xoá chiến dịch thất bại: ${error.message}`);
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

    const user = await this.getSessionUser(token);
    if (!user) throw new UnauthorizedException("Phiên đăng nhập không hợp lệ");

    // const isPublisher = await this.hasRole(user.user_id, "B");
    // if (!isPublisher)
    //   throw new BadRequestException("Chỉ Publisher (role B) mới được đăng ký nhận chiến dịch.");

    const { data: campaign } = await supabase
      .from("campaigns")
      .select("status")
      .eq("campaign_id", campaign_id)
      .single();

    if (!campaign) throw new BadRequestException("Không tìm thấy chiến dịch");
    if (campaign.status !== "ACTIVE")
      throw new BadRequestException("Chỉ có thể đăng ký nhận chiến dịch đang active");

    const { data, error } = await supabase
      .from("campaign_applications")
      .insert({ campaign_id, B_id: user.id, status: "1" })
      .select()
      .single();

    if (error) {
      if (error.code === "23505")
        throw new BadRequestException("Bạn đã đăng ký nhận chiến dịch này rồi");
      throw new BadRequestException(`Đăng ký nhận thất bại: ${error.message}`);
    }

    return { application: data };
  }

  // ── Campaign: Role A xem các đơn đăng ký của campaign ──────────────────────
  @Get("campaigns/:id/applications")
  @HttpCode(HttpStatus.OK)
  async getApplicationsByCampaign(
    @Req() req: Request,
    @Param("id") campaign_id: number,
  ) {
    const token = req.cookies["access_token"];
    if (!token) throw new UnauthorizedException("Chưa đăng nhập");

    const user = await this.getSessionUser(token);
    if (!user) throw new UnauthorizedException("Phiên đăng nhập không hợp lệ");

    const { data: camp } = await supabase
      .from("campaigns")
      .select("owner_id")
      .eq("campaign_id", campaign_id)
      .single();

    if (!camp || camp.owner_id !== user.id)
      throw new BadRequestException("Bạn không có quyền xem đơn của chiến dịch này");

    const { data, error } = await supabase
      .from("campaign_applications")
      .select("*")
      .eq("campaign_id", campaign_id)

    if (error) throw new BadRequestException(`Lấy danh sách đơn thất bại: ${error.message}`);
    return { applications: data ?? [] };
  }

  // ── Campaign: Role A duyệt / từ chối đơn ────────────────────────────────
  @Patch("applications/:guid")
  @HttpCode(HttpStatus.OK)
  async reviewApplication(
    @Req() req: Request,
    @Param("guid") guid: string,
    @Body() body: any,
  ) {
    const token = req.cookies["access_token"];
    if (!token) throw new UnauthorizedException("Chưa đăng nhập");

    const user = await this.getSessionUser(token);
    if (!user) throw new UnauthorizedException("Phiên đăng nhập không hợp lệ");

    const { decision } = body;
    if (decision !== "APPROVED" && decision !== "REJECTED") {
      throw new BadRequestException(
        "decision phải là 'approved' hoặc 'rejected'",
      );
    }

    const { data: app } = await supabase
      .from("campaign_applications")
      .select("campaign_id")
      .eq("guid", guid)
      .single();

    if (!app) throw new BadRequestException("Không tìm thấy đơn đăng ký");

    const { data: camp } = await supabase
      .from("campaigns")
      .select("owner_id")
      .eq("campaign_id", app.campaign_id)
      .single();

    if (!camp || camp.owner_id !== user.id)
      throw new BadRequestException("Bạn không có quyền duyệt đơn của chiến dịch này");

    const { data, error } = await supabase
      .from("campaign_applications")
      .update({ status: decision, modified_at: new Date().toISOString() })
      .eq("guid", guid)
      .select()
      .single();

    if (error || !data) throw new BadRequestException(`Duyệt đơn thất bại: ${error?.message}`);

    return { application: data };
  }

  // ── Campaign: Role B xem các đơn mình đã đăng ký ──────────────────────────
  @Get("my-applications")
  @HttpCode(HttpStatus.OK)
  async getMyApplications(@Req() req: Request) {
    const token = req.cookies["access_token"];
    if (!token) throw new UnauthorizedException("Chưa đăng nhập");

    const user = await this.getSessionUser(token);
    if (!user) throw new UnauthorizedException("Phiên đăng nhập không hợp lệ");

    const { data, error } = await supabase
      .from("campaign_applications")
      .select("*")
      .eq("publisher_id", user.id)
      .order("applied_at", { ascending: false });

    if (error) throw new BadRequestException(`Lấy đơn đăng ký thất bại: ${error.message}`);
    return { applications: data ?? [] };
  }
}
