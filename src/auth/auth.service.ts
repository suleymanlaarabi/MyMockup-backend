import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { AuthBody } from './auth.controller';
import { PrismaService } from 'src/prisma.service';
import { compare, hash } from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { UserPayload } from './jwt.strategy';
import { AuthError } from './auth.error.enum';
import { CreateUserDto } from './dto/create-user.dto';
import { User } from '@prisma/client';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
  ) {}

  async login(authBody: AuthBody) {
    const { email, password } = authBody;

    const existingUser = await this.findUserByEmail(email);

    this.ensureUserExists(existingUser);

    await this.validatePassword(password, existingUser.password);

    return await this.authenticateUser(existingUser.id);
  }

  async register(registerBody: CreateUserDto) {
    const { email, password, firstName } = registerBody;

    const existingUser = await this.findUserByEmail(email);

    this.ensureUserExists(existingUser);

    const hashedPassword = await this.hashPassword(password);

    const createdUser = await this.createUser(email, hashedPassword, firstName);

    return await this.authenticateUser(createdUser.id);
  }

  private async findUserByEmail(email: string) {
    return await this.prisma.user.findUnique({ where: { email } });
  }

  private ensureUserExists(user: User | null) {
    if (!user) {
      throw new HttpException(AuthError.USER_NOT_EXIST, HttpStatus.NOT_FOUND);
    }
  }

  private async validatePassword(
    plainPassword: string,
    hashedPassword: string,
  ) {
    const isPasswordValid = await compare(plainPassword, hashedPassword);

    if (!isPasswordValid) {
      throw new HttpException(
        AuthError.INVALID_PASSWORD,
        HttpStatus.UNAUTHORIZED,
      );
    }
  }

  private async createUser(
    email: string,
    hashedPassword: string,
    firstName: string,
  ) {
    return await this.prisma.user.create({
      data: { email, password: hashedPassword, firstName },
    });
  }

  async hashPassword(password: string) {
    return hash(password, 10);
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
