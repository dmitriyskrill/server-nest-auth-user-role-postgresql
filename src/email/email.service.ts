import { Injectable } from "@nestjs/common";
import { createTransport } from "nodemailer";
import * as Mail from "nodemailer/lib/mailer";
import { ConfigService } from "@nestjs/config";

@Injectable()
export default class EmailService {
  private nodemailerTransport: Mail;

  constructor(
    private readonly configService: ConfigService
  ) {
    this.nodemailerTransport = createTransport({
      service: configService.get("EMAIL_SERVICE"),
      auth: {
        user: configService.get("EMAIL_USER"),
        pass: configService.get("EMAIL_PASSWORD")
      }
    });
  }

  async sendActivationMail({ to, link }) {
    await this.nodemailerTransport.sendMail({
      from: this.configService.get("EMAIL_USER"),
      to,
      subject: `Активация аккаунта на ${this.configService.get("API_URL")}`,
      text: "text",
      html:
        `
          <div>
            <h1>Для активации аккаунта перейдите по ссылке</h1>
            <a href="${link}">${link}</a>
          </div>
        `
    });
  }

  sendMail(options: Mail.Options) {
    return this.nodemailerTransport.sendMail(options);
  }
}