import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import cookieParser from 'cookie-parser';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  
  // Sử dụng middleware cookie-parser để đọc token từ req.cookies
  app.use(cookieParser());
  
  const PORT = process.env.PORT || 3000;
  await app.listen(PORT);
  console.log(`🚀 Authorize server (NestJS) đang chạy tại http://localhost:${PORT}`);
}
bootstrap();
