import { supabase } from "./db/db";
import {
  Campaign,
  CampaignApplication,
  CampaignFull,
  CreateCampaignInput,
  UpdateCampaignInput,
} from "./db/Campaign";

// ─── Helper: kiểm tra user có role không ─────────────────────────────────────
async function hasRole(user_id: string, roleName: string): Promise<boolean> {
  const { data } = await supabase
    .from("user_roles")
    .select("roles(role_name)")
    .eq("user_id", user_id);

  return (data ?? []).some((r: any) => r.roles?.role_name === roleName);
}

// ─── Tạo campaign mới (CHỈ role A — Advertiser) ───────────────────────────────
export async function createCampaign(
  owner_id: string,
  input: CreateCampaignInput,
): Promise<CampaignFull> {
  // 1. Kiểm tra role A
  const isAdvertiser = await hasRole(owner_id, "A");
  if (!isAdvertiser)
    throw new Error(
      "Chỉ Advertiser (role A) mới được tạo chiến dịch. Hãy đăng ký role A trước.",
    );

  // 2. Validate input
  if (!input.name || input.name.trim() === "")
    throw new Error("Tên chiến dịch không được để trống");

  if (input.budget !== undefined && (isNaN(input.budget) || input.budget < 0))
    throw new Error("Ngân sách phải là số không âm");

  // 3. Insert vào bảng campaigns
  const { data: campaign, error: campaignErr } = await supabase
    .from("campaigns")
    .insert({
      owner_id,
      name: input.name.trim(),
      description: input.description ?? null,
      budget: input.budget ?? null,
      status: "draft",
    })
    .select()
    .single();

  if (campaignErr || !campaign)
    throw new Error(`Tạo chiến dịch thất bại: ${campaignErr?.message}`);

  // 4. Insert target (nếu có)
  let targets: any[] = [];
  if (input.target) {
    const { data: targetRow, error: targetErr } = await supabase
      .from("campaign_targets")
      .insert({
        campaign_id: campaign.campaign_id,
        job_fields: input.target.job_fields ?? null,
        regions: input.target.regions ?? null,
      })
      .select()
      .single();

    if (targetErr) throw new Error(`Tạo target thất bại: ${targetErr.message}`);
    targets = [targetRow];
  }

  return { ...(campaign as Campaign), targets, metrics: [] };
}

// ─── Lấy danh sách campaign của một Advertiser (role A) ──────────────────────
export async function getCampaignsByOwner(
  owner_id: string,
): Promise<Campaign[]> {
  const { data, error } = await supabase
    .from("campaigns")
    .select("*")
    .eq("owner_id", owner_id)
    .order("created_at", { ascending: false });

  if (error)
    throw new Error(`Lấy danh sách chiến dịch thất bại: ${error.message}`);
  return (data ?? []) as Campaign[];
}

// ─── Lấy danh sách campaign active (CHỈ role B — Publisher mới xem được) ──────
export async function getActiveCampaigns(
  publisher_id: string,
): Promise<Campaign[]> {
  // const isPublisher = await hasRole(publisher_id, "B");
  // if (!isPublisher)
  //   throw new Error(
  //     "Chỉ Publisher (role B) mới được xem danh sách campaign để nhận. Hãy đăng ký role B trước.",
  //   );

  const { data, error } = await supabase
    .from("campaigns")
    .select("*")
    .eq("status", "active")
    .order("created_at", { ascending: false });

  if (error)
    throw new Error(`Lấy danh sách chiến dịch thất bại: ${error.message}`);
  return (data ?? []) as Campaign[];
}

// ─── Lấy chi tiết 1 campaign (kèm targets + metrics) ─────────────────────────
export async function getCampaignById(
  campaign_id: string,
): Promise<CampaignFull> {
  const { data: campaign, error: campaignErr } = await supabase
    .from("campaigns")
    .select("*")
    .eq("campaign_id", campaign_id)
    .single();

  if (campaignErr || !campaign) throw new Error("Không tìm thấy chiến dịch");

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
    ...(campaign as Campaign),
    targets: targets ?? [],
    metrics: metrics ?? [],
  };
}

// ─── Cập nhật campaign (CHỈ owner — role A) ──────────────────────────────────
export async function updateCampaign(
  campaign_id: string,
  owner_id: string,
  input: UpdateCampaignInput,
): Promise<Campaign> {
  if (input.start_date && input.end_date) {
    if (new Date(input.end_date) < new Date(input.start_date))
      throw new Error("Ngày kết thúc phải sau ngày bắt đầu");
  }

  const { data, error } = await supabase
    .from("campaigns")
    .update({ ...input, updated_at: new Date().toISOString() })
    .eq("campaign_id", campaign_id)
    .eq("owner_id", owner_id) // chỉ owner mới được sửa
    .select()
    .single();

  if (error || !data)
    throw new Error(`Cập nhật chiến dịch thất bại: ${error?.message}`);
  return data as Campaign;
}

// ─── Xoá campaign (CHỈ owner — role A) ───────────────────────────────────────
export async function deleteCampaign(
  campaign_id: string,
  owner_id: string,
): Promise<void> {
  const { error } = await supabase
    .from("campaigns")
    .delete()
    .eq("campaign_id", campaign_id)
    .eq("owner_id", owner_id);

  if (error) throw new Error(`Xoá chiến dịch thất bại: ${error.message}`);
}

// ─── Role B đăng ký nhận campaign ────────────────────────────────────────────
export async function applyToCampaign(
  publisher_id: string,
  campaign_id: string,
  note?: string,
): Promise<CampaignApplication> {
  // 1. Kiểm tra role B
  const isPublisher = await hasRole(publisher_id, "B");
  if (!isPublisher)
    throw new Error("Chỉ Publisher (role B) mới được đăng ký nhận chiến dịch.");

  // 2. Campaign phải đang active
  const { data: campaign } = await supabase
    .from("campaigns")
    .select("status")
    .eq("campaign_id", campaign_id)
    .single();

  if (!campaign) throw new Error("Không tìm thấy chiến dịch");
  if (campaign.status !== "active")
    throw new Error("Chỉ có thể đăng ký nhận chiến dịch đang active");

  // 3. Insert đơn đăng ký
  const { data, error } = await supabase
    .from("campaign_applications")
    .insert({ campaign_id, publisher_id, note: note ?? null })
    .select()
    .single();

  if (error) {
    // Trùng lặp (UNIQUE constraint)
    if (error.code === "23505")
      throw new Error("Bạn đã đăng ký nhận chiến dịch này rồi");
    throw new Error(`Đăng ký nhận thất bại: ${error.message}`);
  }

  return data as CampaignApplication;
}

// ─── Role A duyệt / từ chối đơn đăng ký ─────────────────────────────────────
export async function reviewApplication(
  owner_id: string,
  application_id: string,
  decision: "approved" | "rejected",
): Promise<CampaignApplication> {
  // Lấy application để kiểm tra owner
  const { data: app } = await supabase
    .from("campaign_applications")
    .select("campaign_id")
    .eq("application_id", application_id)
    .single();

  if (!app) throw new Error("Không tìm thấy đơn đăng ký");

  // Kiểm tra owner của campaign
  const { data: camp } = await supabase
    .from("campaigns")
    .select("owner_id")
    .eq("campaign_id", app.campaign_id)
    .single();

  if (!camp || camp.owner_id !== owner_id)
    throw new Error("Bạn không có quyền duyệt đơn của chiến dịch này");

  const { data, error } = await supabase
    .from("campaign_applications")
    .update({ status: decision, reviewed_at: new Date().toISOString() })
    .eq("application_id", application_id)
    .select()
    .single();

  if (error || !data) throw new Error(`Duyệt đơn thất bại: ${error?.message}`);
  return data as CampaignApplication;
}

// ─── Lấy danh sách đơn đăng ký của campaign (role A xem) ─────────────────────
export async function getApplicationsByCampaign(
  owner_id: string,
  campaign_id: string,
): Promise<CampaignApplication[]> {
  // Kiểm tra ownership
  const { data: camp } = await supabase
    .from("campaigns")
    .select("owner_id")
    .eq("campaign_id", campaign_id)
    .single();

  if (!camp || camp.owner_id !== owner_id)
    throw new Error("Bạn không có quyền xem đơn của chiến dịch này");

  const { data, error } = await supabase
    .from("campaign_applications")
    .select("*")
    .eq("campaign_id", campaign_id)
    .order("applied_at", { ascending: false });

  if (error) throw new Error(`Lấy danh sách đơn thất bại: ${error.message}`);
  return (data ?? []) as CampaignApplication[];
}

// ─── Lấy danh sách đơn đăng ký của Publisher (role B xem đơn của mình) ───────
export async function getMyApplications(
  publisher_id: string,
): Promise<CampaignApplication[]> {
  const { data, error } = await supabase
    .from("campaign_applications")
    .select("*")
    .eq("publisher_id", publisher_id)
    .order("applied_at", { ascending: false });

  if (error) throw new Error(`Lấy đơn đăng ký thất bại: ${error.message}`);
  return (data ?? []) as CampaignApplication[];
}
