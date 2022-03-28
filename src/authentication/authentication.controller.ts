import {
  Body, Controller, Get, HttpCode, HttpStatus, Post, Req, Res, UseGuards
} from "@nestjs/common";
import { AuthDto } from "./dto/auth.dto";
import { AuthenticationService } from "./authentication.service";
import { ApiTags } from "@nestjs/swagger";
import RegisterDto from "./dto/register.dto";
import JwtRefreshGuard from "./guards/jwt-refresh.guard";
import { Response } from "express";
import { LocalAuthenticationGuard } from "./guards/localAuthentication.guard";
import JwtAuthenticationGuard from "./guards/jwt-authentication.guard";
import RequestWithUser from "./interfaces/requestWithUser.interface";
import { UsersService } from "../users/users.service";
import { EmailConfirmationService } from "../emailConfirmation/emailConfirmation.service";
import { ConfigService } from "@nestjs/config";

@ApiTags("Авторизация")
@Controller("auth")
export class AuthenticationController {
  constructor(
    private readonly authService: AuthenticationService,
    private readonly usersService: UsersService,
    private readonly configService: ConfigService,
    private readonly emailConfirmationService: EmailConfirmationService
  ) {
  }

  @HttpCode(200)
  @UseGuards(LocalAuthenticationGuard)
  @Post("/login")
  async login(
    @Body() authDto: AuthDto,
    @Res() res: Response
  ) {
    const tokenDto = await this.authService.login(authDto);
    await this.usersService.setCurrentRefreshToken(
      tokenDto.refreshToken, tokenDto.userId
    );
    res.status(HttpStatus.OK).send(tokenDto);
  }

  @Post("/registration")
  async registration(
    @Body() registerDto: RegisterDto,
    @Res() res: Response
  ) {
    const tokenDto = await this.authService.registration(registerDto);
    await this.emailConfirmationService.sendVerificationLink(registerDto.email);
    res.status(HttpStatus.CREATED).send(tokenDto);
  }

  @UseGuards(JwtRefreshGuard)
  @Get("/updateAccessToken")
  async updateAccessToken(@Req() request: RequestWithUser) {
    return this.authService.generateAccessToken(request.user.id)
  }

  @UseGuards(JwtAuthenticationGuard)
  @Get()
  authenticate(@Req() request: RequestWithUser) {
    const user = request.user;
    delete user.password;
    return user;
  }

  @UseGuards(JwtAuthenticationGuard)
  @Post("logout")
  @HttpCode(200)
  async logout(@Req() request: RequestWithUser) {
    await this.usersService.removeRefreshToken(request.user.id);
  }
}
