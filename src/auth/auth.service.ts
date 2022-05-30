import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { Prisma } from '../../prisma/prisma/client';
import PrismaClientKnownRequestError = Prisma.PrismaClientKnownRequestError;

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}
  async signup(dto: AuthDto) {
    // Generate the password hash
    const hash = await argon.hash(dto.password);
    try {
      // Save the new user in the database
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash,
        },
      });

      delete user.hash;
      // Return created user
      return user;
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('Credentials taken ');
        }
      }
      throw error;
    }
  }

  async login(dto: AuthDto) {
    // Find user by email
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });

    if (!user) {
      throw new ForbiddenException('Credentials incorrect');
    }

    if (!(await argon.verify(user.hash, dto.password)))
      throw new ForbiddenException('Incorrect password');

    delete user.hash;
    return user;
  }
}
