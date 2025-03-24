import {
  Body,
  Controller,
  Headers,
  Post,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dto/auth.dto';

@Controller('api/auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('signup')
  signup(@Body() dto: AuthDto) {
    return this.authService.signup(dto);
  }
  @Post('login')
  login(@Body() dto: AuthDto) {
    return this.authService.login(dto);
  }
    @Post('logout')
  async logout(@Headers('authorization') authHeader: string) {
    return this.authService.logout(authHeader);
  }
}
