import { BadRequestException, Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';

import * as bcryptjs from 'bcryptjs'

import { User } from './entities/user.entity';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload';
import { LoginResponse } from './interfaces/login-response';
import { RegisterDto,CreateUserDto, LoginDto, UpdateAuthDto } from './dto';

@Injectable()
export class AuthService {

  constructor(@InjectModel(User.name) private userModel: Model<User>,
  private jwtService: JwtService
){}

  async create(createUserDto: CreateUserDto): Promise<User>{

    try {
      const {password, ...userData} = createUserDto;
      const newUser = new this.userModel({
        password: bcryptjs.hashSync(password, 10),
        ...userData
      });

      await newUser.save();

      const { password:_,...user} = newUser.toJSON();

      return user;
      
    } catch (error) {
      if(error.code === 11000){
        throw new BadRequestException(`${ createUserDto.email} already exists!`);
      }
      else {
        throw new BadRequestException(`Bad request!`);
      }
    }

  }

  async register(registerDto: RegisterDto): Promise<LoginResponse>{
        
    if(registerDto.password !== registerDto.passwordConfirm) { throw new BadRequestException(`Passwords must match!`); }

    const {passwordConfirm, ...userData} = registerDto;
    const userToCreate = <CreateUserDto>{
      ...userData
    }

    const user = await this.create(userToCreate);

    const reponse = {
      token: this.getJwtToken({id: user._id}),
      user
    }
    
    return reponse;

  }

  async login(loginDto: LoginDto): Promise<LoginResponse>{
    const {email, password} = loginDto; 

    const user = await this.userModel.findOne({email});
    if(!user || !bcryptjs.compareSync(password, user.password)) {
      throw new UnauthorizedException('Not valid credentials');
    }

    const { password: _, ...rest } = user.toJSON();

    const reponse = {
      token: this.getJwtToken({id: user.id}),
      user: rest
    }
    
    return reponse;
  }

  findAll(): Promise<User[]> {
    const usersList = this.userModel.find();
    return usersList;
  }

  async findUserById(id: string) {
    const user = await this.userModel.findById(id);

    const {password, ...rest} = user.toJSON();

    return rest;

  }

  getJwtToken(payload: JwtPayload) {
    const token = this.jwtService.sign(payload)

    return token;
  }

  generateNewToken(user: User): LoginResponse{
    return {
      user,
      token: this.getJwtToken({id: user._id})
    } 
  }

  // findOne(id: number) {
  //   return `This action returns a #${id} auth`;
  // }

  // update(id: number, updateAuthDto: UpdateAuthDto) {
  //   return `This action updates a #${id} auth`;
  // }

  // remove(id: number) {
  //   return `This action removes a #${id} auth`;
  // }




}
