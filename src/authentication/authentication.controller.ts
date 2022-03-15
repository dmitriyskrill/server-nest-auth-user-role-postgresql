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
    res.setHeader(
      "Set-Cookie",
      this.authService.getCookiesJwt(tokenDto)
    );
    res.status(HttpStatus.CREATED).send(tokenDto);
  }

  @Post("/registration")
  async registration(
    @Body() registerDto: RegisterDto,
    @Res() res: Response
  ) {
    const tokenDto = await this.authService.registration(registerDto);
    res.setHeader(
      "Set-Cookie",
      this.authService.getCookiesJwt(tokenDto)
    );
    await this.emailConfirmationService.sendVerificationLink(registerDto.email);
    res.status(HttpStatus.CREATED).send(tokenDto);
  }

  @UseGuards(JwtRefreshGuard)
  @Get("/updateAccessCookie")
  async updateAccessToken(@Req() request: RequestWithUser) {
    const accessTokenCookie = this.authService.generateAndGetCookieJwtAccessToken(
      request.user.id
    );
    request.res.setHeader("Set-Cookie", accessTokenCookie);
    return request.user;
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
    request.res.setHeader("Set-Cookie", this.authService.getCookieForLogOut());
  }
}
