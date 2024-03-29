import { Injectable } from '@nestjs/common';
import { User } from '@prisma/client';
import { PrismaService } from 'src/prisma.service';

@Injectable()
export class UsersService {
  constructor(private readonly prisma: PrismaService) {}

  async getUser(id: string) {
    const user = await this.prisma.user.findFirst({
      select: {
        id: true,
        email: true,
        firstName: true,
      },
      where: {
        id,
      },
    });
    return user;
  }
  async getUsers() {
    const users = await this.prisma.user.findMany({
      select: {
        id: true,
        email: false,
        firstName: true,
      },
    });

    return users;
  }
}
