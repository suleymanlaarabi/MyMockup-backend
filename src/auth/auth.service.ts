import { Injectable } from '@nestjs/common';
import { AuthBody } from './auth.controller';
import { PrismaService } from 'src/prisma.service';
import { compare, hash } from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
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
      throw new Error("L'utilisateur n'existe pas");
    }

    const isPasswordValid = await this.isPasswordValid(
      password,
      existingUser.password,
    );

    if (!isPasswordValid) {
      throw new Error('le mot de passe est invalide');
    }

    return await this.authenticateUser(existingUser.id);
  }

  async hashPassword(password: string) {
    return hash(password, 10);
  }

  async isPasswordValid(password: string, hashedPassword: string) {
    return await compare(password, hashedPassword);
  }

  private async authenticateUser(userId: string) {
    const payload = {
      sub: userId,
    };
    return {
      access_token: await this.jwtService.signAsync(payload),
    };
  }
}
