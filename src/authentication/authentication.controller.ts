import {
  Body, ClassSerializerInterceptor,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  Res,
  UseGuards,
  UseInterceptors
} from "@nestjs/common";
import { AuthDto } from "./dto/auth.dto";
import { AuthenticationService } from "./authentication.service";
import { ApiTags } from "@nestjs/swagger";
import RegisterDto from "./dto/register.dto";
import JwtRefreshGuard from "./jwt-refresh.guard";
import { Response, Request } from "express";
import { LocalAuthenticationGuard } from "./localAuthentication.guard";
import JwtAuthenticationGuard from "./jwt-authentication.guard";
import RequestWithUser from "./interfaces/requestWithUser.interface";
import { UsersService } from "../users/users.service";
import { JwtService } from "@nestjs/jwt";
import { ExtractJwt } from "passport-jwt";
import { ConfigService } from "@nestjs/config";

@ApiTags("Авторизация")
@Controller("auth")
export class AuthenticationController {
  constructor(
    private readonly authService: AuthenticationService,
    private readonly usersService: UsersService,
    private readonly configService: ConfigService,
    private jwtService: JwtService
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
    res.status(HttpStatus.CREATED).send(tokenDto);
  }

  @UseGuards(JwtRefreshGuard)
  @Get("/refresh")
  async refreshAccessToken(@Req() request: RequestWithUser) {
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