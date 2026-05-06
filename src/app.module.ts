import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { CampaignController } from './campaign.controller';

@Module({
  imports: [],
  controllers: [AuthController, CampaignController],
  providers: [],
})
export class AppModule {}
