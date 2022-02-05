import { HttpException, HttpStatus, Injectable } from "@nestjs/common";
import { Repository } from "typeorm";
import { InjectRepository } from "@nestjs/typeorm";

import { User } from "./user.entity";
import { CreateUserDto } from "./dto/create-user.dto";
import { UpdateUserDto } from "./dto/update-user.dto";

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User)
    private usersRepository: Repository<User>
  ) {
  }

  async create(createUserDto: CreateUserDto): Promise<User> {
    try {
      const newUser = await this.usersRepository.create(createUserDto);
      await this.usersRepository.save(newUser);
      return newUser;
    } catch (e) {
      console.log(e);
      throw new HttpException(
        e.message + e.detail,
        HttpStatus.BAD_REQUEST
      );
    }

  }

  findAll(): Promise<User[]> {
    return this.usersRepository.find();
  }

  findOne(id: number): Promise<User> {
    return this.usersRepository.findOne(id);
  }

  update(id: number, updateUserDto: UpdateUserDto) {
    return `This action updates a #${id} user`;
  }

  async remove(id: number): Promise<void> {
    await this.usersRepository.delete(id);
  }

  async getByLogin(login: string) {
    const user = await this.usersRepository.findOne({ login });
    if (user) {
      return user;
    }
    throw new HttpException(
      `Пользователь с login: ${login} не найден`,
      HttpStatus.NOT_FOUND
    );
  }

  async getByEmail(email: string) {
    const user = await this.usersRepository.findOne({ email });
    if (user) {
      return user;
    }

    throw new HttpException(
      `Пользователь с email: ${email} не найден`,
      HttpStatus.NOT_FOUND
    );
  }
}
