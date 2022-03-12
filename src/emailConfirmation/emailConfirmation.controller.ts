import {
  Controller,
  ClassSerializerInterceptor,
  UseInterceptors,
  Post,
  UseGuards,
  Req, Get, Query
} from "@nestjs/common";
import ConfirmEmailDto from './dto/confirmEmail.dto';
import { EmailConfirmationService } from './emailConfirmation.service';
import JwtAuthenticationGuard from '../authentication/guards/jwt-authentication.guard';
import RequestWithUser from '../authentication/interfaces/requestWithUser.interface';

@Controller('email-confirmation')
@UseInterceptors(ClassSerializerInterceptor)
export class EmailConfirmationController {
  constructor(
    private readonly emailConfirmationService: EmailConfirmationService
  ) {}

  @Get('confirm')
  async confirm(@Query() confirmationData: ConfirmEmailDto) {
    const email = await this.emailConfirmationService.decodeConfirmationToken(confirmationData.token);
    await this.emailConfirmationService.confirmEmail(email);
  }

  @Post('resend-confirmation-link')
  @UseGuards(JwtAuthenticationGuard)
  async resendConfirmationLink(@Req() request: RequestWithUser) {
    await this.emailConfirmationService.resendConfirmationLink(request.user.id);
  }
}