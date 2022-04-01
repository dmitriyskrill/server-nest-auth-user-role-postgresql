import { Controller, Get, Post, Body, Patch, Param, Delete, UseGuards } from "@nestjs/common";
import { UsersService } from './users.service';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { ApiOperation, ApiResponse, ApiTags } from "@nestjs/swagger";
import { User } from "./user.entity";
import JwtAuthenticationGuard from "../authentication/guards/jwt-authentication.guard";

@ApiTags('users')
@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @ApiOperation({ summary: "Создать пользователя" })
  @ApiResponse({ status: 200, type: [User] })
  @Post()
  @UseGuards(JwtAuthenticationGuard)
  create(@Body() createUserDto: CreateUserDto) {
    return this.usersService.create(createUserDto);
  }

  // @UseGuards(JwtAuthenticationGuard)
  @Get()
  getAll() {
    return this.usersService.getAll();
  }

  // @UseGuards(JwtAuthenticationGuard)
  @Get(':id')
  getById(@Param('id') id: string) {
    return this.usersService.getById(+id);
  }

  @Patch(':id')
  update(@Param('id') id: string, @Body() updateUserDto: UpdateUserDto) {
    return this.usersService.update(+id, updateUserDto);
  }

  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.usersService.remove(+id);
  }
}
