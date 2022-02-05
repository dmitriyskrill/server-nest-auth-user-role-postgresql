import {
  ArgumentMetadata,
  BadRequestException, HttpException, HttpStatus,
  Injectable,
  PipeTransform
} from "@nestjs/common";
import { validate } from 'class-validator';
import { plainToClass } from 'class-transformer';

@Injectable()
export class ValidationPipe implements PipeTransform<any> {
  async transform(value: any, metadata: ArgumentMetadata): Promise<any> {

    const object = plainToClass(metadata.metatype, value);
    const errors = await validate(object);
    if (errors.length > 0) {
      let messages = errors.map(err => {
        return `${err.property} - ${Object.values(err.constraints).join(', ')}`
      })
      throw new BadRequestException(messages)
    }
    return value;
  }
}