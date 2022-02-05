import { IsEmail, IsOptional, IsString } from "class-validator";
import { ApiProperty, ApiPropertyOptional } from "@nestjs/swagger";
import { validationOptions } from "../../users/user.swagger";

export class RegisterDto {
  @ApiProperty(validationOptions.email)
  @IsString({message: 'Должно быть строкой'})
  @IsEmail({},{message: "Некорректный  email"})
  email: string;

  @ApiProperty(validationOptions.login)
  @IsString({message: 'Должно быть строкой'})
  login: string;

  @ApiProperty(validationOptions.password)
  @IsString({message: 'Должно быть строкой'})
  password: string;

  @ApiPropertyOptional(validationOptions.phoneNumber)
  @IsString({message: 'Должно быть строкой'})
  @IsOptional()
  phoneNumber?: string;
}

export default RegisterDto;
