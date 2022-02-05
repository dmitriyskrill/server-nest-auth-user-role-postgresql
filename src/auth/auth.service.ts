import { HttpException, HttpStatus, Injectable, UnauthorizedException } from "@nestjs/common";
import { CreateUserDto } from "../users/dto/create-user.dto";
import { UsersService } from "../users/users.service";
import { JwtService } from "@nestjs/jwt";
import * as bcrypt from "bcryptjs";
import { User } from "../users/user.entity";
import { AuthDto } from "./dto/auth.dto";
import { TokenDto } from "./dto/token.dto";
import registerDto, { RegisterDto } from "./dto/register.dto";
import EmailService from "../email/email.service";

@Injectable()
export class AuthService {

  constructor(
    private userService: UsersService,
    private jwtService: JwtService,
    private emailService: EmailService
  ) {
  }

  async login(userDto: AuthDto): Promise<TokenDto> {
    const user = await this.validateUser(userDto);
    return this.generateToken(user);
  }

  async registration(registerDto: RegisterDto): Promise<TokenDto> {
    console.log('registration 1');
    const hashPassword = await bcrypt.hash(
      registerDto.password, 10
    );
    console.log('registration 2');
    const user = await this.userService.create({
      ...registerDto, password: hashPassword
    });
    console.log('registration 3');
    await this.emailService.sendActivationMail({
      to: user.email,
      link: 'https://www.google.com/'
    })
    console.log('registration 4');
    return this.generateToken(user);
  }

  private async generateToken(user: User): Promise<TokenDto> {
    const payload = {
      email: user.email, login: user.login, id: user.id
    };
    return {
      token: this.jwtService.sign(payload)
    };
  }

  private async validateUser(userDto: AuthDto): Promise<User> {
    const user = await this.userService.getByLogin(userDto.login);
    const passwordEquals = await bcrypt.compare(userDto.password, user.password);
    if (user && passwordEquals) {
      return user;
    }
    throw new UnauthorizedException(
      { message: "Не корректный login или пароль" }
    );
  }

}
