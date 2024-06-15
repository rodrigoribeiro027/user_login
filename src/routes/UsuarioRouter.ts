import { UsuarioCotroller } from "../controllers";
import { Router } from "express";
import { authenticate ,verifyAdm } from "../middleware/authenticate";

const routes = Router();

routes.post("/criar",verifyAdm, UsuarioCotroller.createUsuario);
routes.get("/buscar", UsuarioCotroller.findAllUsuarios);
routes.put("/atualizar/:id", authenticate,UsuarioCotroller.updateUsuario);
routes.delete("/excluir/:id",authenticate ,UsuarioCotroller.deleteUsuario);  
routes.post('/login', UsuarioCotroller.login);

export default routes;
