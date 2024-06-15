import { Request, Response } from 'express';
import UsuarioService from '../services/UsuarioService';
import { generateToken } from '../middleware/authenticate';
import { Usuarios } from '../models/Usuarios';

class UsuarioController {
    public async login(req: Request, res: Response){
        try{
            const { email, senha } = req.body;
            const usuario = await Usuarios.findOne({email: email, senha:senha}, "-__v")
            if(!usuario){
                return res.status(404).json(`usuario não encontrado, email ou senha incorreto....`);
            }
            const token = await generateToken(usuario);
            res.set('Authorization', `Bearer ${token}`);
            return res.status(200).json({message:'Login realizado com sucesso...', token:token});
        }catch(error){
            return res.status(500).json(error);
        }
    }

    public async createUsuario(req: Request, res: Response) {
        try {
            const novoUsuario = req.body;
            const usuario = await UsuarioService.createUsuario(novoUsuario);
            res.status(201).json(usuario);
        } catch (error) {
            console.error('Erro ao criar usuário:', error.message);
            res.status(500).json({ error: error.message });
        }
    }

    public async findAllUsuarios(req: Request, res: Response) {
        try {
            const usuarios = await UsuarioService.findAllUsuario();
            res.status(200).json(usuarios);
        } catch (error) {
            console.error('Erro ao buscar usuários:', error.message);
            res.status(500).json({ error: error.message });
        }
    }

    public async updateUsuario(req: Request, res: Response) {
        try {
            const usuarioId = req.params.id;
            const usuarioData = req.body;
            const updatedUsuario = await UsuarioService.updateUsuario(usuarioId, usuarioData);
            res.status(200).json(updatedUsuario);
        } catch (error) {
            console.error('Erro ao atualizar usuário:', error.message);
            res.status(500).json({ error: error.message });
        }
    }

    public async deleteUsuario(req: Request, res: Response) {
        try {
            const usuarioId = req.params.id;
            const deletedUsuario = await UsuarioService.deleteUsuario(usuarioId);
            res.status(200).json(deletedUsuario);
        } catch (error) {
            console.error('Erro ao deletar usuário:', error.message);
            res.status(500).json({ error: error.message });
        }
    }
}

export default new UsuarioController();