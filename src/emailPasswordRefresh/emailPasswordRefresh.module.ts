import { Module } from "@nestjs/common";
import { ConfigModule } from "@nestjs/config";
import { EmailModule } from "../email/email.module";
import { JwtModule } from "@nestjs/jwt";
import { UsersModule } from "../users/users.module";
import { EmailPasswordRefreshService } from "./emailPasswordRefresh.service";
import { EmailPasswordRefreshController } from "./emailPasswordRefresh.controller";

@Module({
  imports: [ConfigModule, EmailModule, JwtModule.register({}), UsersModule],
  providers: [EmailPasswordRefreshService],
  exports: [EmailPasswordRefreshService],
  controllers: [EmailPasswordRefreshController]
})
export class EmailConfirmationModule {}
