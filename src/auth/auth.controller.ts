import { Body, Controller, Get, Post, Req, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { JwtAuthGuard } from './jwt-auth.guard';
import { RequestWithUser, UserPayload } from './jwt.strategy';
import { UsersService } from 'src/users/users.service';
import { CreateUserDto } from './dto/create-user.dto';

export type AuthBody = { email: string; password: string };

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly userService: UsersService,
  ) {}
  @Post('login')
  async login(@Body() authBody: AuthBody) {
    return await this.authService.login(authBody);
  }
  @Post('register')
  async register(@Body() registerBody: CreateUserDto) {
    return await this.authService.register(registerBody);
  }

  @UseGuards(JwtAuthGuard)
  @Get()
  async authenticate(@Req() { user }: RequestWithUser) {
    console.log(user);
    return await this.userService.getUser(user.userId);
  }
}
