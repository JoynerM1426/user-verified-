const catchError = require('../utils/catchError');
const User = require('../models/User');
const bcrypt = require('bcrypt');
const sendEmail = require('../utils/senEmail');
const EmailCode = require('../models/EmailCode');
const jwt = require('jsonwebtoken')

const getAll = catchError(async(req, res) => {
    const results = await User.findAll();
    return res.json(results);
});

const create = catchError(async(req, res) => {
    const {email, password, firstName, lastName, country, image, frontBaseUrl} = req.body;
    const encripted= await bcrypt.hash(password,10)
    const result = await User.create({email, password: encripted, firstName, lastName, country, image});
    const code= require('crypto').randomBytes(32).toString("hex") //genera el codigo
    const link= `${frontBaseUrl}/verify_email/${code}`;  //toma la base del front y le envia el codigo generado
    await sendEmail ({
      to:email,
      subject:'verify your email',
      html: 
      `      <h1 style= color:gray>
                  Hello ${firstName}
             <h1>
                <p>verify your email <p>
                <p>go to your email<p>
             <a href="${link}"> ${link} <a>
     `
    })
    await EmailCode.create({code, userId: result.id}) //conexion con el modelo de emailsCode
    return res.status(201).json(result);
});

const getOne = catchError(async(req, res) => {
    const { id } = req.params;
    const result = await User.findByPk(id);
    if(!result) return res.sendStatus(404);
    return res.json(result);
});

const remove = catchError(async(req, res) => {
    const { id } = req.params;
    await User.destroy({ where: {id} });
    return res.sendStatus(204);
});

const update = catchError(async(req, res) => {
  const { firstName, lastName, country, image} = req.body;
    const { id } = req.params;
    const result = await User.update(
         { firstName, lastName, country, image} , //elimina actualizar el email y password
        { where: {id}, returning: true }
    );
    if(result[0] === 0) return res.sendStatus(404);
    return res.json(result[1][0]);
});

const verifyEmail= catchError(async(req, res) => {
  const {code}=   req.params;
  const emailCode=  await EmailCode.findOne({where: { code}});
  if(!emailCode) return res.status(401).json({message:"invalid code"})
  await User.update({isVerified:  true}, {where: {id: emailCode.userId}})
  await emailCode.destroy();
  return res.json(emailCode);
});
const login = catchError(async(req, res) => {
    const {email, password} = req.body;
    const user = await User.findOne({where: {email}})
    if(!user) return res.status(401).json({message: "invalid token"})
    if(!user.isVerified) return res.status(401).json({message: "invalid token"})
    const isValid= await bcrypt.compare(password,user.password )  //compara la contrasena sin encriptar con la controsena encriptada
    if(!isValid) return res.status(401).json({message: "invalid token"})
    const token = jwt.sign({user}, process.env.TOKEN_SECRET, {expiresIn:'5d'})
    return res.json({user, token})
});

const getLogedUser = catchError(async(req, res) => {
    return res.json(req.user)
});

// Función para generar y enviar un correo electrónico con un enlace para restablecer la contraseña
const resetPassword = catchError(async (req, res) => {
    const { email, frontBaseUrl } = req.body;
    
  // Buscar el usuario con el correo electrónico ingresado
    const user = await User.findOne({ where: { email } });
    if (!user) return res.status(401).json({ message: "Invalid email" });
//  generar codigo
    const code = require('crypto').randomBytes(32).toString('hex');

    // crea un enlace que envia a al correo con el codigo anterior
    const link = `${frontBaseUrl}/reset_password/${code}`;
  
    await sendEmail({
      to: email,
      subject: 'Reset your password',
      html: `
        <h1 style="color: gray;">Hello ${user.firstName},</h1>
        <p>Please click on the following link to reset your password:</p>
        <a href="${link}">${link}</a>
      `,
    });
   // Guarda el código encriptado en la tabla EmailCode para este usuario
    await EmailCode.create({ code, userId: user.id });
    return res.status(201).json({ message: 'Reset password email sent' });
  });
// Función para restablecer la contraseña del usuario utilizando el código enviado al correo para el cambio de contraseña y la nueva contraseña elegidas
  const resetPasswordConfirm = catchError(async (req, res) => {
     const { code } = req.params;
  const { password } = req.body;
   // Buscar el registro de EmailCode correspondiente al código proporcionado
  const emailCode = await EmailCode.findOne({ where: { code } });
  if (!emailCode) return res.status(401).json({ message: 'Invalid or expired code' });
    // Buscar el usuario correspondiente al registro de EmailCode
  const user = await User.findOne({ where: { id: emailCode.userId } });
  if (!user) return res.status(401).json({ message: 'User not found' });
   // Encriptar la nueva contraseña y actualizarla para el usuario correspondiente
  const hashedPassword = await bcrypt.hash(password, 10);
  await user.update({ password: hashedPassword });
    // Eliminar el registro de EmailCode correspondiente
  await emailCode.destroy();
  return res.status(200).json({ message: 'Password reset successfully' });
  });

module.exports = {
    getAll,
    create,
    getOne,
    remove,
    update,
    verifyEmail,
    login,
    getLogedUser,
    resetPassword, 
    resetPasswordConfirm
   

}