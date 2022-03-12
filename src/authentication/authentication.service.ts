import { HttpException, HttpStatus, Injectable, UnauthorizedException } from "@nestjs/common";
import { UsersService } from "../users/users.service";
import { JwtService } from "@nestjs/jwt";
import * as bcrypt from "bcryptjs";
import { User } from "../users/user.entity";
import { AuthDto } from "./dto/auth.dto";
import { TokenDto } from "./dto/token.dto";
import { RegisterDto } from "./dto/register.dto";
import EmailService from "../email/email.service";
import { ConfigService } from "@nestjs/config";
import PostgresErrorCode from "../database/postgresErrorCode.enum";
import { TUserId } from "../users/interfaces/user-id.interface";

@Injectable()
export class AuthenticationService {

  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
    private emailService: EmailService,
    private readonly configService: ConfigService
  ) {
  }

  public async getAuthenticatedUser(email: string, plainTextPassword: string) {
    try {
      const user = await this.usersService.getByEmail(email);
      await this.verifyPassword(plainTextPassword, user.password);
      delete user.password;
      return user;
    } catch (error) {
      throw new HttpException("Wrong credentials provided", HttpStatus.BAD_REQUEST);
    }
  }

  private async verifyPassword(plainTextPassword: string, hashedPassword: string) {
    const isPasswordMatching = await bcrypt.compare(
      plainTextPassword,
      hashedPassword
    );
    if (!isPasswordMatching) {
      throw new HttpException("Wrong credentials provided", HttpStatus.BAD_REQUEST);
    }
  }

  async login(userDto: AuthDto): Promise<TokenDto> {
    const user = await this.validateUser(userDto);
    return this.generateTokens(user.id);
  }

  async registration(registerDto: RegisterDto): Promise<TokenDto> {
    console.log("registration", registerDto);
    const hashedPassword = await bcrypt.hash(
      registerDto.password, 10
    );
    try {
      const user = await this.usersService.create({
        ...registerDto, password: hashedPassword
      });
      await this.emailService.sendActivationMail({
        to: user.email,
        link: "https://www.google.com/"
      });
      delete user.password;
      return this.generateTokens(user.id);
    } catch (error) {
      if (error?.status === 400) {
        throw new HttpException("Пользователь с таким логином или почтой уже создан", HttpStatus.BAD_REQUEST);
      }
      console.log(error, error.code);
      throw new HttpException("Something went wrong", HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  public getCookiesJwt(tokenDto: TokenDto): string[] {
    const { accessToken, refreshToken } = tokenDto;
    return [
      this.getCookieJwtAccessToken(accessToken),
      this.getCookieJwtRefreshToken(refreshToken)
    ];
  }

  public getCookieJwtAccessToken(token: string): string {
    return `AccessToken=${token}; HttpOnly; Path=/; Max-Age=${this.configService.get("JWT_ACCESS_TOKEN_EXPIRATION_TIME")}`;
  }

  public getCookieJwtRefreshToken(token: string): string {
    return `RefreshToken=${token}; HttpOnly; Path=/; Max-Age=${this.configService.get("JWT_REFRESH_TOKEN_EXPIRATION_TIME")}`;
  }

  public generateAndGetCookieJwtAccessToken(userId: TUserId): string {
    return this.getCookieJwtAccessToken(this.generateAccessToken(userId));
  }

  public getCookieForLogOut() {
    return [
      "AccessToken=; HttpOnly; Path=/; Max-Age=0",
      "RefreshToken=; HttpOnly; Path=/; Max-Age=0"
    ];
  }

  private generateTokens(userId: TUserId): TokenDto {
    return {
      accessToken: this.generateAccessToken(userId),
      refreshToken: this.generateRefreshToken(userId),
      userId
    };
  }

  private generateRefreshToken(userId: TUserId): string {
    return this.jwtService.sign({ userId }, {
      secret: this.configService.get("JWT_REFRESH_TOKEN_SECRET"),
      expiresIn: `${this.configService.get("JWT_REFRESH_TOKEN_EXPIRATION_TIME")}s`
    });
  }

  private generateAccessToken(userId: TUserId): string {
    return this.jwtService.sign({ userId }, {
      secret: this.configService.get("JWT_ACCESS_TOKEN_SECRET"),
      expiresIn: `${this.configService.get("JWT_ACCESS_TOKEN_EXPIRATION_TIME")}s`
    });
  }

  private async validateUser(userDto: AuthDto): Promise<User> {
    const user = await this.usersService.getByEmail(userDto.email);
    const passwordEquals = await bcrypt.compare(userDto.password, user.password);
    if (user && passwordEquals) {
      return user;
    }
    throw new UnauthorizedException(
      { message: "Не корректный login или пароль" }
    );
  }

  public async validateRefreshToken(token: string) {

    const secret = this.configService.get("JWT_REFRESH_TOKEN_SECRET");
    console.log("validateRefreshToken", token, secret);
    return this.jwtService.verify(token, secret);
  }
}
