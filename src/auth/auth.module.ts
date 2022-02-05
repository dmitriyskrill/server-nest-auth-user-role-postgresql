import { forwardRef, Module } from "@nestjs/common";
import { AuthService } from "./auth.service";
import { AuthController } from "./auth.controller";
import { UsersModule } from "../users/users.module";
import { JwtModule } from "@nestjs/jwt";
import { EmailModule } from "../email/email.module";

@Module({
  imports: [
    EmailModule,
    forwardRef(() => UsersModule),
    JwtModule.register({
      secret: process.env.PRIVATE_KEY || "SECRET",
      signOptions: {
        expiresIn: "24h"
      }
    })
  ],
  providers: [AuthService],
  exports: [AuthService],
  controllers: [AuthController]
})
export class AuthModule {
}