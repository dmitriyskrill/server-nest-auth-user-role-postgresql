import { Module } from "@nestjs/common";
import { TypeOrmModule } from "@nestjs/typeorm";

import { UsersModule } from "./users/users.module";
import { User } from "./users/user.entity";
import { AuthModule } from './auth/auth.module';
import { EmailModule } from './email/email.module';
import { ConfigModule } from "@nestjs/config";
import * as Joi from '@hapi/joi';
import { DatabaseModule } from "./database/database.module";

@Module({
  imports: [
    ConfigModule.forRoot({
      validationSchema: Joi.object({
        POSTGRES_HOST: Joi.string().required(),
        POSTGRES_PORT: Joi.number().required(),
        POSTGRES_USER: Joi.string().required(),
        POSTGRES_PASSWORD: Joi.string().required(),
        POSTGRES_DB: Joi.string().required(),
        PORT: Joi.number(),
        EMAIL_SERVICE: Joi.string().required(),
        EMAIL_USER: Joi.string().required(),
        EMAIL_PASSWORD: Joi.string().required(),
      })
    }),
    DatabaseModule,
    UsersModule,
    AuthModule,
    EmailModule
  ],
  controllers: [],
  providers: []
})
export class AppModule {
}
