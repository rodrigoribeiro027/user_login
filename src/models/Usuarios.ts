import mongoose from 'mongoose';

const { Schema } = mongoose;

const usuariosSchema = new Schema({
    nome: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    senha: { type: String, required: true },
    tipoUsuario: { type: Number },
    dataCriacao: { type: Date, default: Date.now }
});

const Usuarios = mongoose.model("Usuarios", usuariosSchema);

export { Usuarios };
