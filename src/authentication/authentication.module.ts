import { forwardRef, Module } from "@nestjs/common";
import { AuthenticationService } from "./authentication.service";
import { AuthenticationController } from "./authentication.controller";
import { UsersModule } from "../users/users.module";
import { JwtModule } from "@nestjs/jwt";
import { EmailConfirmationModule } from "../emailConfirmation/emailConfirmation.module";
import { ConfigModule } from "@nestjs/config";
import { LocalStrategy } from "./strategies/local.strategy";
import { JwtRefreshTokenStrategy } from "./strategies/jwt-refresh-token.strategy";
import { JwtStrategy } from "./strategies/jwt.strategy";
import { PassportModule } from "@nestjs/passport";

@Module({
  imports: [
    ConfigModule,
    EmailConfirmationModule,
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