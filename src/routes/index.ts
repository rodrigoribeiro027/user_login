import { Router } from "express";
import UsuarioRouter from "./UsuarioRouter"

const routes = Router();

routes.get('/', (req, res) => res.json('Is Rodando......') );
routes.use('/usuarios', UsuarioRouter );

export default routes;