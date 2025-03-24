import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtModule } from '@nestjs/jwt';
import { PrismaModule } from 'src/prisma/prisma.module';
import { ConfigModule } from '@nestjs/config';

@Module({
  imports: [JwtModule.register({}), PrismaModule,ConfigModule],
  providers: [AuthService],
  controllers: [AuthController],
})
export class AuthModule {}
