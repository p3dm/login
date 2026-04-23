# Authorize — Tài liệu Setup & Kiến trúc

## Mục lục
1. [Kiến trúc tổng thể](#1-kiến-trúc-tổng-thể)
2. [Cấu hình Supabase Database](#2-cấu-hình-supabase-database)
3. [Biến môi trường](#3-biến-môi-trường)
4. [API Endpoints](#4-api-endpoints)
5. [Luồng hoạt động](#5-luồng-hoạt-động)
6. [Bảo mật Cookie](#6-bảo-mật-cookie)
7. [Chạy project](#7-chạy-project)

---

## 1. Kiến trúc tổng thể

Project dùng **Node.js `http` module thuần** (không có Express/Fastify) + **Supabase Auth** để quản lý xác thực.

```
auth.users (Supabase quản lý)    public.users (ứng dụng quản lý)
─────────────────────────────    ──────────────────────────────
id (uuid)          ──────────→   user_id (uuid, FK)
email                            email
password hash (ẩn hoàn toàn)    full_name
created_at                       age
raw_user_meta_data               job_field
                                 avatar_url
                                 created_at
```

- **`auth.users`**: Supabase Auth quản lý — xác thực, mật khẩu, session, JWT. **KHÔNG** truy cập trực tiếp.
- **`public.users`**: Bảng profile của ứng dụng — dữ liệu người dùng, không chứa `password_hash`.
- **Trigger `handle_new_user`**: Tự động tạo profile trong `public.users` khi có user mới trong `auth.users`.

---

## 2. Cấu hình Supabase Database

Chạy các SQL sau trong **Supabase Dashboard → SQL Editor**:

### Bước 1 — Sửa bảng `public.users`

> Xóa cột `password_hash` (không cần thiết, Supabase Auth lo), đổi `user_id` sang UUID để khớp với `auth.users.id`.

```sql
-- Xóa cột password_hash
ALTER TABLE public.users
  DROP COLUMN IF EXISTS password_hash;

-- Đổi kiểu user_id sang UUID
ALTER TABLE public.users
  ALTER COLUMN user_id TYPE uuid USING gen_random_uuid();

-- Liên kết với auth.users (cascade xóa khi auth user bị xóa)
ALTER TABLE public.users
  ADD CONSTRAINT users_id_fkey
  FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE;
```

### Bước 2 — Tạo Database Trigger

> Khi có user mới đăng ký qua Supabase Auth, trigger tự động tạo profile trong `public.users` từ metadata.

```sql
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS trigger AS $$
BEGIN
  INSERT INTO public.users (user_id, email, full_name, age)
  VALUES (
    NEW.id,
    NEW.email,
    NEW.raw_user_meta_data->>'full_name',
    (NEW.raw_user_meta_data->>'age')::int
  );
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();
```

### Bước 3 — Bật Row Level Security (RLS)

```sql
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;

-- User chỉ đọc được profile của chính mình
CREATE POLICY "Users can view own profile"
  ON public.users FOR SELECT
  USING (auth.uid() = user_id);

-- User chỉ sửa được profile của chính mình
CREATE POLICY "Users can update own profile"
  ON public.users FOR UPDATE
  USING (auth.uid() = user_id);
```

---

## 3. Biến môi trường

Copy file `.env.example` thành `.env` và điền thông tin:

```env
SUPABASE_URL=https://<project-id>.supabase.co
SUPABASE_ANON_KEY=<anon-public-key>
NODE_ENV=development   # hoặc production
PORT=3000
```

> **Lưu ý:** `access_token` và `refresh_token` do **Supabase Auth tự tạo** (JWT được ký bằng `JWT_SECRET` nội bộ của Supabase). Bạn **không cần** tự tạo JWT key.

---

## 4. API Endpoints

Server chạy tại `http://localhost:3000`

| Method | Endpoint  | Mô tả                        | Auth yêu cầu |
|--------|-----------|------------------------------|--------------|
| GET    | `/`       | Health check                 | Không        |
| POST   | `/signUp` | Đăng ký tài khoản mới        | Không        |
| POST   | `/login`  | Đăng nhập                    | Không        |
| POST   | `/logout` | Đăng xuất                    | Không        |
| GET    | `/me`     | Lấy thông tin user hiện tại  | Cookie       |

### POST `/signUp`
```json
// Request Body
{
  "email": "user@example.com",
  "password": "matkhau123",
  "full_name": "Nguyen Van A",
  "age": 25
}

// Response 200 — email confirmation TẮT
{
  "message": "Đăng ký thành công",
  "user": { "user_id": "...", "email": "...", "full_name": "...", ... }
}

// Response 200 — email confirmation BẬT
{
  "message": "Đăng ký thành công",
  "user": null,
  "message": "Vui lòng kiểm tra email để xác nhận tài khoản"
}
// Set-Cookie: access_token=...; refresh_token=...
```

### POST `/login`
```json
// Request Body
{ "email": "user@example.com", "password": "matkhau123" }

// Response 200
{ "message": "Đăng nhập thành công", "user": { ...SafeUser } }
// Set-Cookie: access_token=...; refresh_token=...
```

### POST `/logout`
```
// Không cần body
// Response 200
{ "message": "Đã đăng xuất" }
// Set-Cookie: access_token= (xóa cookie)
```

### GET `/me`
```
// Yêu cầu: cookie access_token phải tồn tại

// Response 200
{ "user": { ...SafeUser } }

// Response 401
{ "message": "Chưa đăng nhập" }
{ "message": "Phiên đăng nhập không hợp lệ" }
```

---

## 5. Luồng hoạt động

### Đăng ký (signUp)
```
Client → POST /signUp { email, password, full_name, age }
  └→ supabase.auth.signUp({ options.data: { full_name, age } })
       ├→ Supabase Auth tạo user trong auth.users
       ├→ Trigger handle_new_user() tự INSERT vào public.users
       └→ session != null? → set cookie + trả về user
                            → session = null → "kiểm tra email"
```

### Đăng nhập (signIn)
```
Client → POST /login { email, password }
  └→ supabase.auth.signInWithPassword()
       └→ Supabase trả về { session: { access_token, refresh_token, expires_in } }
            └→ Server lưu token vào HttpOnly cookie
                 └→ Query public.users lấy profile → trả về SafeUser
```

### Xác thực mỗi request (GET /me)
```
Client → GET /me (cookie access_token tự đính kèm)
  └→ parseCookies(req.headers.cookie)
       └→ supabase.auth.getUser(access_token)
            └→ Supabase verify JWT → trả về user info
                 └→ Query public.users lấy profile → trả về SafeUser
```

---

## 6. Bảo mật Cookie

| Thuộc tính      | Giá trị          | Tác dụng                             |
|-----------------|------------------|--------------------------------------|
| `HttpOnly`      | ✅ Bật           | JavaScript client không đọc được     |
| `SameSite`      | `Strict`         | Chống tấn công CSRF                  |
| `Secure`        | Chỉ production   | Chỉ gửi qua HTTPS                   |
| `Max-Age` (access)  | `expires_in` (~3600s) | access_token hết hạn ~1 giờ  |
| `Max-Age` (refresh) | `604800s`    | refresh_token hết hạn 7 ngày        |

---

## 7. Chạy project

```bash
# Cài dependencies
npm install

# Chạy dev server (hot reload)
npm run dev

# Build production
npm run build
```

Server khởi động tại: `http://localhost:3000`
