import {
  HttpException,
  HttpStatus,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto/auth.dto';
import * as bcrypt from 'bcrypt';
import { ConfigService } from '@nestjs/config';
import { Request, Response } from 'express';
@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private config: ConfigService,
  ) {}

  async signup(dto: AuthDto, res: Response) {
    try {
      const existingUser = await this.prisma.user.findUnique({
        where: { email: dto.email },
      });
      if (existingUser) {
        throw new HttpException('User Already exists', HttpStatus.BAD_REQUEST);
      }
      const hashedPassword = await bcrypt.hash(dto.password, 10);

      const user = await this.prisma.user.create({
        data: {
          name: dto.name,
          email: dto.email,
          password: hashedPassword,
        },
      });
      const tokens = await this.generateTokens(user.id, user.email);
      await res.cookie('refreshToken', tokens.refreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: 'none',
        maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
      });
      return res.status(201).json({
        message: 'User registered successfully',
        accessToken: tokens.accessToken,
      });
    } catch (error) {
      if (error instanceof HttpException) {
        throw error; 
      }
      throw new HttpException(
        'Something went wrong',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  async login(dto: AuthDto, res: Response) {
    try {
      const user = await this.prisma.user.findUnique({
        where: { email: dto.email },
      });
      if (!user) {
        throw new HttpException('User not found', HttpStatus.NOT_FOUND);
      }
      const isPasswordValid = await bcrypt.compare(dto.password, user.password);
      if (!isPasswordValid) {
        throw new HttpException('Invalid credentials', HttpStatus.UNAUTHORIZED);
      }
      const tokens = await this.generateTokens(user.id, user.email);

      await res.cookie('refreshToken', tokens.refreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: 'none',
        maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
      });
      return res.status(201).json({
        message: 'User logged-in successfully',
        accessToken: tokens.accessToken,
      });
    } catch (error) {
      if (error instanceof HttpException) {
        throw error; 
      }
      throw new HttpException(
        'Something went wrong',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }
  async logout(req: Request, res: Response) {
    try {
      const refreshToken = req.cookies.refreshToken;
      console.log('Refresh Token:', refreshToken); 
      
      if (!refreshToken) {
        res.clearCookie('refreshToken', {
          httpOnly: true,
          secure: true,
          sameSite: 'none',
        });
        return res.status(200).json({ message: 'User logged out successfully' });
      }

      const payload = this.jwtService.verify(refreshToken, {
        secret: this.config.get<string>('REFRESH_SECRET'),
      });
        console.log('Payload:', payload);
        
      if (!payload) {
        throw new HttpException('Invalid refresh token', HttpStatus.UNAUTHORIZED);
      }

      await this.prisma.user.update({
        where: { id: payload.sub },
        data: { refreshToken: null },
      });

      res.clearCookie('refreshToken', {
        httpOnly: true,
        secure: true,
        sameSite: 'none',
      });

      return res.status(200).json({ message: 'User logged out successfully' });
    } catch (error) {
      // Clear cookie even if there's an error
      res.clearCookie('refreshToken', {
        httpOnly: true,
        secure: true,
        sameSite: 'none',
      });

      if (error instanceof HttpException) {
        throw error;
      }
      
      // Handle JWT verification errors (expired, malformed, etc.)
      if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
        return res.status(200).json({ message: 'User logged out successfully' });
      }

      throw new HttpException('Logout failed', HttpStatus.INTERNAL_SERVER_ERROR);
    }
}
  

  async generateTokens(userId: string, email: string) {
    const payload = { sub: userId, email };
    const accessToken = this.jwtService.sign(payload, {
      secret: this.config.get<string>('ACCESS_SECRET'),
      expiresIn: '15m',
    });

    const refreshToken = this.jwtService.sign(payload, {
      secret: this.config.get<string>('REFRESH_SECRET'),
      expiresIn: '7d',
    });

    await this.updateRefreshToken(userId, refreshToken);
    return { accessToken, refreshToken };
  }

  async updateRefreshToken(userId: string, refreshToken: string) {
    const hashedToken = await bcrypt.hash(refreshToken, 10);
    await this.prisma.user.update({
      where: { id: userId },
      data: { refreshToken: hashedToken },
    });
  }
  async refresh(req: Request, res: Response) {
    try {
  
      const refreshToken = req.cookies['refreshToken'];
      
      if (!refreshToken) {
        console.error('CRITICAL: No refresh token found in cookies');
        throw new UnauthorizedException('No refresh token provided');
      }
  
      let payload;
      try {
        payload = this.jwtService.verify(refreshToken, {
          secret: this.config.get<string>('REFRESH_SECRET')
        });
      } catch (verifyError) {
        console.error('Token Verification Failed:', verifyError);
        throw new UnauthorizedException('Invalid or expired refresh token');
      }
  
      const user = await this.prisma.user.findUnique({
        where: { id: payload.sub },
        select: { 
          id: true, 
          email: true, 
          refreshToken: true 
        }
      });
  
      if (!user) {
        console.error('No user found with ID:', payload.sub);
        throw new UnauthorizedException('User not found');
      }
  
      // If you're unsure about the comparison, add more logging
      const isRefreshTokenValid = await bcrypt.compare(
        refreshToken, 
        user.refreshToken || ''
      );
  
      if (!isRefreshTokenValid) {
        throw new UnauthorizedException('Invalid refresh token');
      }
  
      const tokens = await this.generateTokens(user.id, user.email);
  
      // More flexible cookie settings for testing
      res.cookie('refreshToken', tokens.refreshToken, {
        httpOnly: true,
        secure: false, // Set to false for local testing
        sameSite: 'lax',
        maxAge: 1000 * 60 * 60 * 24 * 7,
      });
  
      return res.status(200).json({
        message: 'Token refreshed successfully',
        accessToken: tokens.accessToken
      });
  
    } catch (error) {
      console.error('Comprehensive Refresh Error:', error);
      
      throw new HttpException(
        error.message || 'Token refresh failed', 
        error.status || HttpStatus.UNAUTHORIZED
      );
    }
  }
}
