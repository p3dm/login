# Authorize — Backend Xác Thực với Supabase & Cookie

## Mục Lục
- [Tổng Quan](#tổng-quan)
- [Cấu Trúc Thư Mục](#cấu-trúc-thư-mục)
- [Thiết Kế Database](#thiết-kế-database)
- [Luồng Xác Thực](#luồng-xác-thực)
- [API Routes](#api-routes)
- [Thiết Kế Cookie](#thiết-kế-cookie)
- [Giải Thích Từng File](#giải-thích-từng-file)
- [Cách Chạy](#cách-chạy)

---

## Tổng Quan

Dự án này là một **authentication backend** viết bằng Node.js + TypeScript, sử dụng **Supabase** làm cơ sở dữ liệu và xác thực. Sau khi đăng nhập thành công, server trả về **HttpOnly cookie** chứa JWT token để bảo vệ phiên làm việc.

```
Client (Browser)
    │
    │  POST /login  { email, password }
    ▼
Node.js HTTP Server (index.ts)
    │
    ├── supabase.auth.signInWithPassword()   ← xác thực credentials
    ├── SELECT * FROM users WHERE email = ?  ← lấy thông tin profile
    └── SELECT roles FROM user_roles         ← lấy vai trò người dùng
    │
    │  Set-Cookie: access_token (HttpOnly)
    │  Set-Cookie: refresh_token (HttpOnly)
    ▼
Client nhận cookie, tự động gửi kèm mọi request tiếp theo
```

---

## Cấu Trúc Thư Mục

```
Authorize/
├── src/
│   ├── index.ts          # HTTP Server & định nghĩa các Routes
│   ├── login.ts          # Logic xác thực: login, logout, getSessionUser
│   ├── db.ts             # Khởi tạo Supabase client
│   └── User.ts           # TypeScript interfaces & types
├── .env                  # Biến môi trường (không commit lên git)
├── .env.example          # Mẫu file .env
├── tsconfig.json         # Cấu hình TypeScript
└── package.json
```

---

## Thiết Kế Database

### Bảng `users`
| Cột | Kiểu | Mô tả |
|-----|------|-------|
| `user_id` | int4 (PK) | ID người dùng |
| `email` | varchar (UNIQUE) | Email — dùng để liên kết với Supabase Auth |
| `password_hash` | text | Mật khẩu đã mã hóa (do Supabase Auth quản lý) |
| `created_at` | timestamp | Thời điểm tạo tài khoản |
| `full_name` | text | Họ tên đầy đủ |
| `age` | int4 | Tuổi |
| `job_field` | text | Lĩnh vực công việc |
| `avatar_url` | text | Đường dẫn ảnh đại diện |

### Bảng `roles`
| Cột | Kiểu | Mô tả |
|-----|------|-------|
| `role_id` | int4 (PK) | ID vai trò |
| `role_name` | varchar (UNIQUE) | Tên vai trò (vd: `admin`, `user`) |

### Bảng `user_roles` *(bảng trung gian)*
| Cột | Kiểu | Mô tả |
|-----|------|-------|
| `user_id` | int4 (FK → users) | Người dùng |
| `role_id` | int4 (FK → roles) | Vai trò |

> 💡 Một user có thể có **nhiều roles** (Many-to-Many thông qua `user_roles`).

---

## Luồng Xác Thực

### Đăng Nhập (`POST /login`)

```
1. Client gửi { email, password }
2. supabase.auth.signInWithPassword() → xác thực, nhận session (JWT)
3. Query bảng "users" theo email → lấy profile
4. Query bảng "user_roles" JOIN "roles" → lấy danh sách roles
5. Xóa password_hash khỏi response (SafeUser)
6. Ghi JWT vào HttpOnly cookie
7. Trả về thông tin user (không có password_hash)
```

### Xác Thực Phiên (`GET /me`)

```
1. Client gửi request kèm cookie tự động
2. Server đọc access_token từ cookie
3. supabase.auth.getUser(token) → xác minh JWT còn hợp lệ
4. Query lại profile + roles từ DB
5. Trả về thông tin user hiện tại
```

### Đăng Xuất (`POST /logout`)

```
1. supabase.auth.signOut() → hủy session trên Supabase
2. Set-Cookie với Max-Age=0 → xóa cookie trên browser
```

---

## API Routes

| Method | Route | Mô tả | Body / Cookie |
|--------|-------|--------|--------------|
| `GET` | `/` | Health check | — |
| `POST` | `/login` | Đăng nhập | Body: `{ email, password }` |
| `POST` | `/logout` | Đăng xuất | Cookie: `access_token` |
| `GET` | `/me` | Lấy thông tin user hiện tại | Cookie: `access_token` |

### Response mẫu `POST /login`

```json
{
  "message": "Đăng nhập thành công",
  "user": {
    "user_id": 1,
    "email": "user@example.com",
    "full_name": "Nguyễn Văn A",
    "age": 25,
    "job_field": "Software Engineer",
    "avatar_url": null,
    "created_at": "2024-01-01T00:00:00Z",
    "roles": ["admin", "user"]
  }
}
```

---

## Thiết Kế Cookie

Sau khi đăng nhập, server trả về **2 cookies**:

| Cookie | Giá trị | Max-Age | Mô tả |
|--------|---------|---------|-------|
| `access_token` | JWT | `expires_in` (vd: 3600s) | Dùng để xác thực mọi request |
| `refresh_token` | Refresh JWT | 7 ngày (604800s) | Dùng để lấy `access_token` mới khi hết hạn |

### Các flag bảo mật trên cookie

| Flag | Tác dụng |
|------|----------|
| `HttpOnly` | JavaScript phía browser **không đọc được** cookie → chống XSS |
| `SameSite=Strict` | Cookie chỉ gửi từ cùng origin → chống CSRF |
| `Path=/` | Cookie áp dụng cho toàn bộ domain |
| `Secure` *(production)* | Chỉ gửi qua HTTPS → bật tự động khi `NODE_ENV=production` |

---

## Giải Thích Từng File

### `src/User.ts` — Type Definitions

```typescript
// Interface ánh xạ 1-1 với bảng "users" trong DB
interface User { user_id, email, password_hash, ... }

// Interface ánh xạ với bảng "roles"
interface Role { role_id, role_name }

// User kèm danh sách role names
interface UserWithRoles extends User { roles: string[] }

// SafeUser: KHÔNG có password_hash — dùng để trả về cho client
type SafeUser = Omit<User, "password_hash"> & { roles: string[] }
```

> ⚠️ `password_hash` **không bao giờ** được gửi về phía client. TypeScript enforces điều này qua kiểu `SafeUser`.

### `src/login.ts` — Auth Logic

| Function | Mô tả |
|----------|-------|
| `parseCookies(header)` | Parse chuỗi cookie từ request header thành object |
| `buildCookies(...)` | Tạo `Set-Cookie` strings với đầy đủ security flags |
| `login(email, password)` | Xác thực + lấy profile + roles + trả về cookies & SafeUser |
| `logout()` | Sign out Supabase + trả về cookies xóa (Max-Age=0) |
| `getSessionUser(token)` | Xác minh JWT từ cookie + trả về SafeUser hiện tại |

### `src/index.ts` — HTTP Server & Routes

- Dùng **Node.js built-in `http`** module (không dùng Express)
- Mỗi route đọc body bằng `readBody<T>()` (stream-based JSON parsing)
- Tất cả lỗi được bắt bởi `try/catch` và trả về status 500

### `src/db.ts` — Supabase Client

- Khởi tạo `SupabaseClient` từ `SUPABASE_URL` và `SUPABASE_ANON_KEY`
- Đọc từ file `.env` qua `dotenv/config`
- Throw lỗi sớm nếu thiếu biến môi trường

---

## Cách Chạy

### 1. Cài đặt dependencies
```bash
npm install
```

### 2. Cấu hình môi trường
```bash
# Copy file mẫu
copy .env.example .env
# Điền SUPABASE_URL và SUPABASE_ANON_KEY vào .env
```

### 3. Chạy server
```bash
npm run dev
```

### 4. Test API

```bash
# Đăng nhập
curl -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"user@example.com\",\"password\":\"matkhau\"}" \
  -c cookies.txt

# Xem thông tin user hiện tại
curl http://localhost:3000/me -b cookies.txt

# Đăng xuất
curl -X POST http://localhost:3000/logout -b cookies.txt -c cookies.txt
```
