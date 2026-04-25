// Định nghĩa kiểu dữ liệu khớp với bảng "users" trong Supabase
export interface User {
  user_id: number;
  email: string;
  password_hash: string;
  created_at: string;
  full_name: string | null;
  age: number | null;
  job_field: string | null;
  avatar_url: string | null;
}

// Matches the "roles" table
export interface Role {
  role_id: number;
  role_name: string;
}

// User with their roles joined
export interface UserWithRoles extends User {
  roles: string[];
}

// What we return to the client (never expose password_hash)
export type SafeUser = Omit<User, "password_hash"> & { roles: string[] | null };
