import { User } from "../user.entity";
import { OmitType, PartialType } from "@nestjs/swagger";

export class UpdateUserDto extends PartialType(
  OmitType(User, ["banned", "id"])
) {
}
