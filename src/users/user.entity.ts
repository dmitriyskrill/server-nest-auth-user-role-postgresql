import { Entity, Column, PrimaryGeneratedColumn } from "typeorm";
import { ApiProperty } from "@nestjs/swagger";
import { validationOptions } from "./user.swagger";
import { Exclude } from "class-transformer";

@Entity()
export class User {
  @ApiProperty(validationOptions.id)
  @PrimaryGeneratedColumn()
  id: number;

  @ApiProperty(validationOptions.email)
  @Column({ unique: true })
  public email: string;

  @ApiProperty(validationOptions.login)
  @Column({ unique: true })
  public login: string;

  @ApiProperty(validationOptions.phoneNumber)
  @Column({ nullable: true })
  public phoneNumber?: string;

  @ApiProperty(validationOptions.password)
  @Column()
  // @Exclude()
  public password: string;

  @Column({ nullable: true })
  // @Exclude()
  public currentHashedRefreshToken?: string;

  @ApiProperty({ example: "true", description: "Забанен или нет" })
  @Column({ default: false })
  banned: boolean;

  @Column({ default: false })
  public isEmailConfirmed: boolean;

  @Column({ default: false })
  public isPhoneNumberConfirmed: boolean;
}