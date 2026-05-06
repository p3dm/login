// ─── Campaign Status ──────────────────────────────────────────────────────────
export type CampaignStatus = "draft" | "active" | "paused" | "ended";

// ─── Campaign (row trong bảng campaigns) ─────────────────────────────────────
export interface Campaign {
  campaign_id: string;
  owner_id: string;
  name: string;
  description: string | null;
  status: CampaignStatus;
  budget: number | null;
  created_at: string;
  updated_at: string;
}

// ─── Campaign Target (row trong bảng campaign_targets) ───────────────────────
export interface CampaignTarget {
  target_id: string;
  campaign_id: string;
  age_min: number | null;
  age_max: number | null;
  job_fields: string[] | null;
  regions: string[] | null;
}

// ─── Campaign Metric (row trong bảng campaign_metrics) ───────────────────────
export interface CampaignMetric {
  metric_id: string;
  campaign_id: string;
  impressions: number;
  clicks: number;
  conversions: number;
  spend: number;
  recorded_at: string;
}

// ─── Campaign với đầy đủ quan hệ (join targets + metrics) ────────────────────
export interface CampaignFull extends Campaign {
  targets: CampaignTarget[];
  metrics: CampaignMetric[];
}

// ─── Input để tạo campaign mới ───────────────────────────────────────────────
export interface CreateCampaignInput {
  name: string;
  description?: string;
  budget?: number;
  target?: {
    job_fields?: string[];
    regions?: string[];
  };
}

// ─── Input để cập nhật campaign ──────────────────────────────────────────────
export interface UpdateCampaignInput {
  name?: string;
  description?: string;
  status?: CampaignStatus;
  budget?: number;
  start_date?: string;
  end_date?: string;
}

// ─── Trạng thái đơn đăng ký nhận campaign (role B) ───────────────────────────
export type ApplicationStatus = "pending" | "approved" | "rejected";

// ─── Campaign Application — role B đăng ký nhận campaign ─────────────────────
export interface CampaignApplication {
  application_id: string;
  campaign_id: string;
  publisher_id: string;
  status: ApplicationStatus;
  note: string | null;
  applied_at: string;
  reviewed_at: string | null;
}
