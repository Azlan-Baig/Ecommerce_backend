import { Body, Controller, Post, Req, Res } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dto/auth.dto';
import { Request, Response } from 'express';

@Controller('api/auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('signup')
  signup(@Body() dto: AuthDto, @Res() res: Response) {
    return this.authService.signup(dto, res);
  }
  @Post('login')
  login(@Body() dto: AuthDto, @Res() res: Response) {
    return this.authService.login(dto, res);
  }
  @Post('logout')
  async logout(@Req() req: Request, @Res() res: Response) {
    return this.authService.logout(req, res);
  }
  @Post('refresh')
  async refresh(@Req() req: Request, @Res() res: Response) {
    return this.authService.refresh(req, res);
  }
}
