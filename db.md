# 📦 Database Schema — Login & Campaign System

> **Database**: Supabase (PostgreSQL)  
> **Auth**: Supabase Auth (`auth.users`) + custom `users` table  

---

## 📐 Entity Relationship Overview

```
auth.users (Supabase managed)
    │
    └──► users (profile)
              │
              ├──► user_roles ──► roles
              │                   (A: advertiser, B: publisher, admin)
              │
              └──► campaigns  [chỉ role A tạo được]
                        │
                        ├──► campaign_targets
                        ├──► campaign_metrics
                        └──► campaign_applications  [role B đăng ký nhận]
                                    │
                                    └──► users (publisher)
```

---

## 👥 Vai trò người dùng (Roles)

| Role    | Tên đầy đủ    | Tự đăng ký | Quyền hạn                                |
|---------|---------------|------------|------------------------------------------|
| `A`     | Advertiser    | ✅ Có      | Tạo, sửa, xoá campaign                  |
| `B`     | Publisher     | ✅ Có      | Xem danh sách campaign, đăng ký nhận     |
| `admin` | Administrator | ❌ Không   | Quản lý toàn bộ hệ thống, gán/thu hồi role |

> **Lưu ý bảo mật:** User chỉ được tự đăng ký role `A` hoặc `B`. Role `admin` chỉ do admin gán.

---

## 🗄️ Tables

### 1. `users` — Hồ sơ người dùng

> Được tạo tự động bởi trigger khi `auth.users` có bản ghi mới.

| Column       | Type          | Constraints            | Description               |
|--------------|---------------|------------------------|---------------------------|
| `user_id`    | `UUID`        | PK, FK → auth.users.id | ID khớp với Supabase Auth |
| `email`      | `TEXT`        | UNIQUE, NOT NULL        | Email đăng nhập           |
| `full_name`  | `TEXT`        | NOT NULL                | Họ và tên                 |
| `age`        | `INT`         |                         | Tuổi                      |
| `job_field`  | `TEXT`        |                         | Lĩnh vực nghề nghiệp      |
| `avatar_url` | `TEXT`        |                         | URL ảnh đại diện          |
| `created_at` | `TIMESTAMPTZ` | DEFAULT now()           | Ngày tạo tài khoản        |

---

### 2. `roles` — Vai trò hệ thống

| Column      | Type   | Constraints      | Description                    |
|-------------|--------|------------------|--------------------------------|
| `role_id`   | `INT`  | PK, SERIAL       | ID vai trò                     |
| `role_name` | `TEXT` | UNIQUE, NOT NULL | Tên vai trò: `A`, `B`, `admin` |

**Dữ liệu mặc định:**
```sql
INSERT INTO roles (role_name) VALUES ('A'), ('B'), ('admin') ON CONFLICT DO NOTHING;
```

---

### 3. `user_roles` — Gán vai trò cho user

| Column    | Type   | Constraints                     | Description |
|-----------|--------|---------------------------------|-------------|
| `user_id` | `UUID` | FK → users.user_id, NOT NULL    | Người dùng  |
| `role_id` | `INT`  | FK → roles.role_id, NOT NULL    | Vai trò     |

**PK**: `(user_id, role_id)`

---

### 4. `campaigns` — Chiến dịch marketing (chỉ role A tạo)

| Column        | Type            | Constraints                    | Description                                      |
|---------------|-----------------|--------------------------------|--------------------------------------------------|
| `campaign_id` | `UUID`          | PK, DEFAULT gen_random_uuid()  | ID chiến dịch                                    |
| `owner_id`    | `UUID`          | FK → users.user_id, NOT NULL   | Người tạo (phải có role A)                       |
| `name`        | `TEXT`          | NOT NULL                       | Tên chiến dịch                                   |
| `description` | `TEXT`          |                                | Mô tả chiến dịch                                 |
| `status`      | `TEXT`          | DEFAULT 'draft'                | Trạng thái: `draft`, `active`, `paused`, `ended` |
| `budget`      | `NUMERIC(15,2)` |                                | Ngân sách (VND)                                  |
| `start_date`  | `DATE`          |                                | Ngày bắt đầu                                     |
| `end_date`    | `DATE`          |                                | Ngày kết thúc                                    |
| `created_at`  | `TIMESTAMPTZ`   | DEFAULT now()                  | Ngày tạo                                         |
| `updated_at`  | `TIMESTAMPTZ`   | DEFAULT now()                  | Ngày cập nhật gần nhất                           |

---

### 5. `campaign_targets` — Đối tượng mục tiêu

| Column        | Type     | Constraints                          | Description                      |
|---------------|----------|--------------------------------------|----------------------------------|
| `target_id`   | `UUID`   | PK, DEFAULT gen_random_uuid()        | ID target                        |
| `campaign_id` | `UUID`   | FK → campaigns.campaign_id, NOT NULL | Thuộc chiến dịch nào             |
| `age_min`     | `INT`    |                                      | Tuổi tối thiểu                   |
| `age_max`     | `INT`    |                                      | Tuổi tối đa                      |
| `job_fields`  | `TEXT[]` |                                      | Mảng lĩnh vực nghề nghiệp        |
| `regions`     | `TEXT[]` |                                      | Mảng khu vực địa lý              |

---

### 6. `campaign_applications` — Role B đăng ký nhận campaign

| Column           | Type          | Constraints                          | Description                                        |
|------------------|---------------|--------------------------------------|----------------------------------------------------|
| `application_id` | `UUID`        | PK, DEFAULT gen_random_uuid()        | ID đơn đăng ký                                     |
| `campaign_id`    | `UUID`        | FK → campaigns.campaign_id, NOT NULL | Campaign muốn nhận                                 |
| `publisher_id`   | `UUID`        | FK → users.user_id, NOT NULL         | Publisher (role B) đăng ký                         |
| `status`         | `TEXT`        | DEFAULT 'pending'                    | Trạng thái: `pending`, `approved`, `rejected`      |
| `note`           | `TEXT`        |                                      | Ghi chú từ publisher                               |
| `applied_at`     | `TIMESTAMPTZ` | DEFAULT now()                        | Thời điểm đăng ký                                  |
| `reviewed_at`    | `TIMESTAMPTZ` |                                      | Thời điểm advertiser duyệt/từ chối                 |

**Ràng buộc:** `(campaign_id, publisher_id)` UNIQUE — mỗi publisher chỉ đăng ký 1 lần/campaign

---

### 7. `campaign_metrics` — Chỉ số hiệu quả

| Column        | Type            | Constraints                          | Description       |
|---------------|-----------------|--------------------------------------|-------------------|
| `metric_id`   | `UUID`          | PK, DEFAULT gen_random_uuid()        | ID metric         |
| `campaign_id` | `UUID`          | FK → campaigns.campaign_id, NOT NULL | Thuộc campaign    |
| `impressions` | `BIGINT`        | DEFAULT 0                            | Số lần hiển thị   |
| `clicks`      | `BIGINT`        | DEFAULT 0                            | Số lần click      |
| `conversions` | `BIGINT`        | DEFAULT 0                            | Số lần chuyển đổi |
| `spend`       | `NUMERIC(15,2)` | DEFAULT 0                            | Chi tiêu (VND)    |
| `recorded_at` | `TIMESTAMPTZ`   | DEFAULT now()                        | Thời điểm ghi     |

---

## 🔐 SQL Setup (Supabase)

```sql
-- Bảng users
CREATE TABLE IF NOT EXISTS public.users (
  user_id    UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  email      TEXT UNIQUE NOT NULL,
  full_name  TEXT NOT NULL,
  age        INT,
  job_field  TEXT,
  avatar_url TEXT,
  created_at TIMESTAMPTZ DEFAULT now()
);

-- Bảng roles (A = Advertiser, B = Publisher)
CREATE TABLE IF NOT EXISTS public.roles (
  role_id   SERIAL PRIMARY KEY,
  role_name TEXT UNIQUE NOT NULL
);
INSERT INTO public.roles (role_name) VALUES ('A'), ('B'), ('admin') ON CONFLICT DO NOTHING;

-- Bảng user_roles
CREATE TABLE IF NOT EXISTS public.user_roles (
  user_id UUID REFERENCES public.users(user_id) ON DELETE CASCADE,
  role_id INT  REFERENCES public.roles(role_id) ON DELETE CASCADE,
  PRIMARY KEY (user_id, role_id)
);

-- Bảng campaigns
CREATE TABLE IF NOT EXISTS public.campaigns (
  campaign_id  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id     UUID NOT NULL REFERENCES public.users(user_id) ON DELETE CASCADE,
  name         TEXT NOT NULL,
  description  TEXT,
  status       TEXT NOT NULL DEFAULT 'draft'
               CHECK (status IN ('draft','active','paused','ended')),
  budget       NUMERIC(15,2) CHECK (budget >= 0),
  start_date   DATE,
  end_date     DATE,
  created_at   TIMESTAMPTZ DEFAULT now(),
  updated_at   TIMESTAMPTZ DEFAULT now(),
  CONSTRAINT end_after_start CHECK (
    end_date IS NULL OR start_date IS NULL OR end_date >= start_date
  )
);

-- Bảng campaign_targets
CREATE TABLE IF NOT EXISTS public.campaign_targets (
  target_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  campaign_id  UUID NOT NULL REFERENCES public.campaigns(campaign_id) ON DELETE CASCADE,
  age_min      INT,
  age_max      INT,
  job_fields   TEXT[],
  regions      TEXT[]
);

-- Bảng campaign_applications (role B nhận campaign)
CREATE TABLE IF NOT EXISTS public.campaign_applications (
  application_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  campaign_id    UUID NOT NULL REFERENCES public.campaigns(campaign_id) ON DELETE CASCADE,
  publisher_id   UUID NOT NULL REFERENCES public.users(user_id) ON DELETE CASCADE,
  status         TEXT NOT NULL DEFAULT 'pending'
                 CHECK (status IN ('pending','approved','rejected')),
  note           TEXT,
  applied_at     TIMESTAMPTZ DEFAULT now(),
  reviewed_at    TIMESTAMPTZ,
  UNIQUE (campaign_id, publisher_id)
);

-- Bảng campaign_metrics
CREATE TABLE IF NOT EXISTS public.campaign_metrics (
  metric_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  campaign_id  UUID NOT NULL REFERENCES public.campaigns(campaign_id) ON DELETE CASCADE,
  impressions  BIGINT DEFAULT 0,
  clicks       BIGINT DEFAULT 0,
  conversions  BIGINT DEFAULT 0,
  spend        NUMERIC(15,2) DEFAULT 0,
  recorded_at  TIMESTAMPTZ DEFAULT now()
);

-- RLS: chỉ service_role mới được gán role admin
ALTER TABLE public.user_roles ENABLE ROW LEVEL SECURITY;
CREATE POLICY "users_can_read_own_roles"
  ON public.user_roles FOR SELECT
  USING (auth.uid() = user_id);
-- INSERT policy được kiểm soát ở application layer (selfAssignRole chỉ cho A và B)
```
