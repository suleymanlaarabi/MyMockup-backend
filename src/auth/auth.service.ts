import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { AuthBody } from './auth.controller';
import { PrismaService } from 'src/prisma.service';
import { compare, hash } from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { UserPayload } from './jwt.strategy';
import { AuthError } from './auth.error.enum';
import { CreateUserDto } from './dto/create-user.dto';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
  ) {}
  async login(authBody: AuthBody) {
    const { email, password } = authBody;

    const existingUser = await this.prisma.user.findUnique({
      where: {
        email: email,
      },
    });

    if (!existingUser) {
      throw new HttpException(AuthError.USER_NOT_EXIST, HttpStatus.NOT_FOUND);
    }
    const isPasswordValid = await this.isPasswordValid(
      password,
      existingUser.password,
    );

    if (!isPasswordValid) {
      throw new HttpException(
        AuthError.INVALID_PASSWORD,
        HttpStatus.UNAUTHORIZED,
      );
    }
    return await this.authenticateUser(existingUser.id);
  }

  async register(registerBody: CreateUserDto) {
    const { email, password, firstName } = registerBody;

    const existingUser = await this.prisma.user.findUnique({
      where: {
        email,
      },
    });

    if (existingUser) {
      throw new HttpException(
        AuthError.EMAIL_ALREADY_IN_USE,
        HttpStatus.CONFLICT,
      );
    }

    const hashedPassword = await this.hashPassword(password);

    const createdUser = await this.prisma.user.create({
      data: {
        email,
        password: hashedPassword,
        firstName,
      },
    });

    return await this.authenticateUser(createdUser.id);
  }

  async hashPassword(password: string) {
    return hash(password, 10);
  }

  async isPasswordValid(password: string, hashedPassword: string) {
    return await compare(password, hashedPassword);
  }

  async authenticateUser(userId: string) {
    const payload: UserPayload = {
      userId,
    };
    return {
      access_token: await this.jwtService.signAsync(payload),
    };
  }
}
