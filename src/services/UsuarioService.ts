import { Usuarios } from "../models/Usuarios";

class UsuarioService {
    generateToken(user: { nome: string; email: string; dataCriacao: Date; tipoUsuario?: number; _id: import("mongoose").Types.ObjectId; }) {
        throw new Error('Method not implemented.');
    }
    public async createUsuario(usuario) {
        try {
            if (!usuario.nome || !usuario.email || !usuario.senha) {
                throw new Error("Todos os campos (nome, email, senha ) são obrigatórios.");
            }
            const user = await Usuarios.create(usuario);
            return user;
        } catch (error) {
            throw error;
        }
    }

    public async findAllUsuario() {
        try {
            const usuarios = await Usuarios.find();
            return usuarios;
        } catch (error) {
            throw error;
        }
    }

    public async updateUsuario(id: string, usuarioData: any) {
        try {
            const usuario = await Usuarios.findByIdAndUpdate(id, {}, { new: true });
            if (!usuario) {
                throw new Error(`Usuário ${id} não encontrado.`);
            }

            if (usuarioData.nome) {
                usuario.nome = usuarioData.nome;
            }
            if (usuarioData.email) {
                usuario.email = usuarioData.email;
            }
            if (usuarioData.senha) {
                usuario.senha = usuarioData.senha;
            }
            const updatedUsuario = await usuario.save();
            return updatedUsuario;
        } catch (error) {
            throw error;
        }
    }

    public async deleteUsuario(id: string) {
        try {
            const deleteUsuario = await Usuarios.findByIdAndDelete(id);
            return deleteUsuario;
        } catch (error) {
            throw error;
        }
    }
}

export default new UsuarioService();
