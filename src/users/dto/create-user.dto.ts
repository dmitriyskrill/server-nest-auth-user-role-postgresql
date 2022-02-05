import { IsEmail, IsString } from "class-validator";
import { ApiProperty, ApiPropertyOptional } from "@nestjs/swagger";
import { validationOptions } from "../user.swagger";

export class CreateUserDto {
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
  phoneNumber?: string;
}

export default CreateUserDto;
