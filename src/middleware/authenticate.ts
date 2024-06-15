import jwt from 'jsonwebtoken';
import * as dotenv from "dotenv";
import { Request, Response, NextFunction } from 'express';
import { UserType } from '../utils/enum';


dotenv.config();

const JWT_SECRET = process.env.JWT_SECRET || '2024';
const UNAUTHORIZED_ERROR_MESSAGE = 'Usuario não possui autorização necessaria para está ação....'

export const generateToken = (dados: any) => {
    return jwt.sign({ id: dados._id, email: dados.email, type: dados.type }, JWT_SECRET, { expiresIn: '1h' });
};
export const authenticate = async (req: Request, res: Response, next: NextFunction) => {
    const authorization = req.headers.authorization;
    if (!authorization || !authorization.startsWith('Bearer ')) {
        return res.status(401).json({ error: UNAUTHORIZED_ERROR_MESSAGE });
    }
    try {
        const [, token] = authorization.split(" ");
        const decoded = jwt.verify(token, process.env.JWT_SECRET || '2024');
        res.locals.jwtPayload = decoded;
        return next();
    } catch (error) {
        return res.status(401).json({ error: error.message || UNAUTHORIZED_ERROR_MESSAGE });
    }
};

export const verifyAdm = (req: Request, res: Response, next: NextFunction) => {
    try{
        const user = res.locals.jwtPayload;
        if (user.type === UserType.ADM){
            next();
        }else{
            throw UNAUTHORIZED_ERROR_MESSAGE
        }
    }catch(error){
        res.status(401).json({ error:error.message || UNAUTHORIZED_ERROR_MESSAGE })
    }
}

