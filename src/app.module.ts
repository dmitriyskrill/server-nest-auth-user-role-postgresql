import { Module } from "@nestjs/common";
import { UsersModule } from "./users/users.module";
import { AuthenticationModule } from './authentication/authentication.module';
import { EmailModule } from './email/email.module';
import { EmailConfirmationModule } from './emailConfirmation/emailConfirmation.module';
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
        JWT_VERIFICATION_TOKEN_SECRET: Joi.string().required(),
        JWT_VERIFICATION_TOKEN_EXPIRATION_TIME: Joi.string().required(),
        EMAIL_CONFIRMATION_URL: Joi.string().required(),
        JWT_REFRESH_TOKEN_SECRET: Joi.string().required(),
        JWT_REFRESH_TOKEN_EXPIRATION_TIME: Joi.string().required(),
        JWT_ACCESS_TOKEN_SECRET: Joi.string().required(),
        JWT_ACCESS_TOKEN_EXPIRATION_TIME: Joi.string().required(),
        API_URL: Joi.string().required(),
      })
    }),
    DatabaseModule,
    UsersModule,
    AuthenticationModule,
    EmailModule,
    EmailConfirmationModule
  ],
  controllers: [],
  providers: []
})
export class AppModule {
}
