import { Body, Controller, Post } from "@nestjs/common";
import { AuthDto } from "./dto/auth.dto";
import { AuthService } from "./auth.service";
import CreateUserDto from "../users/dto/create-user.dto";
import { ApiTags } from "@nestjs/swagger";
import RegisterDto from "./dto/register.dto";

@ApiTags('Авторизация')
@Controller("auth")
export class AuthController {
  constructor(
    private authService: AuthService
  ) {
  }

  @Post("/login")
  login(@Body() authDto: AuthDto) {
    return this.authService.login(authDto);
  }

  @Post("/registration")
  registration(@Body() registerDto: RegisterDto) {
    return this.authService.registration(registerDto);
  }
}
