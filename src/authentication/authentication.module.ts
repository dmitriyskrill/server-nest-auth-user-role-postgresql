import { forwardRef, Module } from "@nestjs/common";
import { AuthenticationService } from "./authentication.service";
import { AuthenticationController } from "./authentication.controller";
import { UsersModule } from "../users/users.module";
import { JwtModule } from "@nestjs/jwt";
import { EmailModule } from "../email/email.module";
import { ConfigModule } from "@nestjs/config";
import { LocalStrategy } from "./local.strategy";
import { JwtRefreshTokenStrategy } from "./jwt-refresh-token.strategy";
import { JwtStrategy } from "./jwt.strategy";
import { PassportModule } from "@nestjs/passport";

@Module({
  imports: [
    ConfigModule,
    EmailModule,
    forwardRef(() => UsersModule),
    JwtModule.register({}),
    PassportModule,
  ],
  providers: [
    AuthenticationService,
    LocalStrategy,
    JwtRefreshTokenStrategy,
    JwtStrategy
  ],
  exports: [AuthenticationService],
  controllers: [AuthenticationController]
})
export class AuthenticationModule {
}