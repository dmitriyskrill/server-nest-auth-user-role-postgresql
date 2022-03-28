import { NestFactory } from "@nestjs/core";
import { SwaggerModule, DocumentBuilder } from "@nestjs/swagger";

import { ValidationPipe } from "./pipes/validation.pipe";
import { AppModule } from "./app.module";
import { ConfigService } from "@nestjs/config";
import * as cookieParser from "cookie-parser";

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const configService = app.get<ConfigService>(ConfigService);
  const port = configService.get("PORT") || 5000;
  const config = new DocumentBuilder()
    .setTitle("Шаблон для авторизации")
    .setDescription("Документация REST API")
    .setVersion("1.0.0")
    .addTag("al-dba")
    .build();
  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup("api", app, document);

  // app.useGlobalPipes(new ValidationPipe());
  app.use(cookieParser());
  app.enableCors({
    origin: true,
    credentials: true
  });
  await app.listen(port, () => {
    console.log(`Server started on port: ${port}`);
  });

}

bootstrap();
