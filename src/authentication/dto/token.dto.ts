import { User } from "../../users/user.entity";
import { TUserId } from "../../users/interfaces/user-id.interface";

export class TokenDto {
  accessToken: string;
  refreshToken: string;
  userId: TUserId
}