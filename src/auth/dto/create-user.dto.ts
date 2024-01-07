import { IsEmail, IsNotEmpty, IsString, MinLength } from 'class-validator';
import { AuthError } from '../auth.error.enum';

export class CreateUserDto {
  @IsEmail(
    {},
    {
      message: AuthError.INVALID_EMAIL,
    },
  )
  email: string;

  @IsNotEmpty()
  @MinLength(6, {
    message: AuthError.INVALID_PASSWORD,
  })
  password: string;

  @IsString()
  firstName: string;
}
