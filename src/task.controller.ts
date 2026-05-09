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

@Controller()
export class taskController {
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

    @Get("task")
    @HttpCode(HttpStatus.OK)
    async getTask(@Req() req: Request, @Param() campaign_id: number) {
        const token = req.cookies["access_token"];
        if (!token) throw new UnauthorizedException("Chưa đăng nhập");

        const user = await this.getSessionUser(token);
        if (!user) throw new UnauthorizedException("Phiên đăng nhập không hợp lệ");

        const { data, error } = await supabase
            .from("task")
            .select("*")
            .eq("campain_id", campaign_id)

        if (data == null || error != null) throw new Error("Không có task");
    }

    //     @Post("task")
    //     @HttpCode(HttpStatus.OK)
    //     async submitTask(@Req() req: Request, @Param() guid: string) {
    //         const token = req.cookies["access_token"];
    //         if (!token) throw new UnauthorizedException("Chưa đăng nhập");

    //         const user = await this.getSessionUser(token);
    //         if (!user) throw new UnauthorizedException("Phiên đăng nhập không hợp lệ!");

    //         const { data, error } = await supabase
    //             .from("task")
    //             .
    //     }
}