import { IsEmail, IsString, MinLength, Equals} from "class-validator";

export class RegisterDto {
    @IsEmail()  
    email: string;

    @IsString()
    name: string;

    @MinLength(6)
    password: string;

    @MinLength(6)
    passwordConfirm: string;
}