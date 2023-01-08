import express from 'express'
const router = express.Router();

import { 
    signin,
    signup,
    googleLogin,
    facebookLogin
} from '../controllers/auth.js';

router.post('/signin', signin);
router.post('/signup', signup);
router.post('/google-login', googleLogin);
router.post('/facebook-login', facebookLogin);

export default router
