import asyncHandler from 'express-async-handler';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import User from '../models/user.js';
import { OAuth2Client } from 'google-auth-library';
import fetch from 'node-fetch';

const signin = asyncHandler(async (req, res) => {
    const { email, password } = req.body;
    // check if user exist
    User.findOne({ email }).exec((err, user) => {
        // authenticate
        if (user) {
            if (bcrypt.compareSync(password, user.passwordHash)) {
                // generate a token and send to client
                const token = jwt.sign(
                    {
                        userId: user.id,
                        isAdmin: user.isAdmin
                    }, 
                    process.env.JWT_SECRET, 
                    { expiresIn: '7d' }
                );
                res.json({ user: user, token: token });
            } else {
                res.status(400).json({
                    error: 'Email and password do not match'
                });
            }
        } else if (!user) {
            res.status(404).json({
                error: 'User with that email does not exist. Please signup'
            });
        } else {
            res.status(500).json({
                error: err
            });
        }
    });
});

const signup = asyncHandler(async (req, res) => {
    const { email } = req.body
    const userExists = await User.findOne({ email })
    if (userExists) {
        res.status(400).send('User already exists')
    } else {
        const user = new User({
            name: req.body.name,
            email: req.body.email,
            passwordHash: bcrypt.hashSync(req.body.passwordHash, 10),
            phone: req.body.phone,
            isAdmin: req.body.isAdmin,
            street: req.body.street,
            apartment: req.body.apartment,
            zip: req.body.zip,
            city: req.body.city,
            country: req.body.country
        });
        const createdUser = await user.save()
        if (user) {
            res.status(201).json(createdUser);
        } else {
            res.status(500).send('Invalid user data')
        }
    }
});

const client = new OAuth2Client(process.env.GOOGLE_OAUTH_CLIENT_ID)

const googleLogin = asyncHandler(async (req, res) => {
    const {idToken} = req.body;
    client.verifyIdToken({idToken, requiredAudience: process.env.GOOGLE_OAUTH_CLIENT_ID}).then(response => {
        // console.log('GOOGLE LOGIN RESPONSE', response)
        const {email_verified, name, email} = response.payload
        if(email_verified) {
            User.findOne({ email }).exec((err, user) => {
                if(user) {
                    // generate a token and send to client
                    const token = jwt.sign({ 
                        userId: user.id,
                        isAdmin: user.isAdmin
                    }, process.env.JWT_SECRET, { expiresIn: '7d' })
                    return res.json({
                        token, 
                        user: user
                    })
                } else {
                    let passwordHash = bcrypt.hashSync(email + process.env.JWT_SECRET, 10)
                    user = new User({name, email, passwordHash})
                    user.save((err, data) => {
                        if(err) {
                            // console.log('ERROR GOOGLE LOGIN ON USER SAVE', err)
                            return res.status(400).json({
                                error: 'User signup failed with google'
                            })
                        }
                        const token = jwt.sign({ 
                            userId: data.userId,
                            isAdmin: data.isAdmin
                        }, process.env.JWT_SECRET, { expiresIn: '7d' })
                        return res.json({
                            token,
                            user: data
                        });
                    });
                }
            });
        } else {
            return res.status(400).json({
                error: 'Google login failed. Try again!'
            })
        }
    })
})

const facebookLogin = asyncHandler(async (req, res) => {
    // console.log('FACEBOOK LOGIN REQ BODY', req.body);
    const {id, authToken} = req.body
    const url = `https://graph.facebook.com/v2.11/${id}/?fields=id, name, email&access_token=${authToken}`
    return(
        fetch(url, {
            method: 'GET'
        })
        .then(response => response.json())
        // .then(response => console.log(response))
        .then(response => {
            const {email, name} = response;
            User.findOne({ email }).exec((err, user) => {
                if(user) {
                    const token = jwt.sign({ 
                        userId: user.id,
                        isAdmin: user.isAdmin
                    }, process.env.JWT_SECRET, { expiresIn: '7d' })
                    return res.json({
                        token, 
                        user: user
                    })
                } else {
                    let passwordHash = bcrypt.hashSync(email + process.env.JWT_SECRET, 10)
                    user = new User({name, email, passwordHash})
                    user.save((err, data) => {
                        if(err) {
                            // console.log('ERROR FACEBOOK LOGIN ON USER SAVE', err)
                            return res.status(400).json({
                                error: 'User signup failed with facebook'
                            })
                        }
                        const token = jwt.sign({ 
                            userId: data.userId,
                            isAdmin: data.isAdmin
                        }, process.env.JWT_SECRET, { expiresIn: '7d' })
                        return res.json({
                            token, 
                            user: data
                        });
                    });
                }
            })
        })
        .catch(() => {
            res.json({
                error: 'Facebook login failed. Try later'
            })
        })
    )
})

export {
    signin,
    signup,
    googleLogin,
    facebookLogin
}