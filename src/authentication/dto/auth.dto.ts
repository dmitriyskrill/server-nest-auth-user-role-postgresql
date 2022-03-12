import { ApiProperty } from "@nestjs/swagger";
import { IsString, Length, IsEmail } from "class-validator";

export class AuthDto {
  @ApiProperty({ example: "email@mail.ru", description: "Почта" })
  @IsString({ message: "Должно быть строкой" })
  @IsEmail({})
  readonly email: string;

  @ApiProperty({ example: "12345", description: "пароль" })
  @IsString({ message: "Должно быть строкой" })
  @Length(4, 16, { message: "Не меньше 4 и не больше 16" })
  readonly password: string;
}