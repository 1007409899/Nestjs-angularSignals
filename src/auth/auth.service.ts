import { BadRequestException, Injectable } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './entities/user.entity';
import { Model } from 'mongoose';
import * as bcryptjs from 'bcryptjs';
import { LoginDto } from './dto/login.dto';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload';
import { LoginResponse } from './interfaces/login-response';
import { RegisterUserDto } from './dto/register-user.dto';
@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name)
    private userModel: Model<User>,
    private jwtService: JwtService,
  ) { }
  async create(createUserDto: CreateUserDto): Promise<User> {
    try {
      const { password, ...userData } = createUserDto;
      const newUser = new this.userModel({
        password: bcryptjs.hashSync(password, 10),
        ...userData,
      });
      //delete password from the response
      await newUser.save();

      const result = newUser.toObject();
      delete result.password;
      return result;
    } catch (error) {
      if (error.code === 11000) {
        throw new BadRequestException('Email already exists');
      }
    }
  }
  async register(registerUserDto: RegisterUserDto): Promise<LoginResponse> {
    const user = await this.create(registerUserDto);
    return {
      user,
      token: this.getJwtToken({ id: user._id }),
    };
  }

  async login(loginDto: LoginDto): Promise<LoginResponse> {
    const { email, password } = loginDto;

    const user = await this.userModel.findOne({ email });
    if (!user) {
      throw new BadRequestException('Invalid credentials');
    }

    if (!bcryptjs.compareSync(password, user.password)) {
      throw new BadRequestException('Constraseña incorrecta');
    }

    const result = user.toObject();
    delete result.password;
    return {
      user: result,
      token: this.getJwtToken({ id: user.id }),
    };
  }
  findAll(): Promise<User[]> {
    return this.userModel.find();
  }

  async findUserById(id: string) {
    const user = await this.userModel.findById(id);
    const result = user.toObject();
    delete result.password;
    return result;
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  getJwtToken(payload: JwtPayload) {
    return this.jwtService.sign(payload);

  }
}
