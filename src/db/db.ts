import { createClient, SupabaseClient } from '@supabase/supabase-js';
import 'dotenv/config';

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseAnonKey = process.env.SUPABASE_ANON_KEY;

if (!supabaseUrl || !supabaseAnonKey) {
  throw new Error(
    '❌ Thiếu biến môi trường SUPABASE_URL hoặc SUPABASE_ANON_KEY.\n' +
    '   Hãy copy file .env.example thành .env và điền thông tin Supabase của bạn.'
  );
}

export const supabase: SupabaseClient = createClient(supabaseUrl, supabaseAnonKey);

console.log('✅ Supabase client đã khởi tạo thành công!');
