const {
    validateEmail,
    validateLength,
    validateUsername
} = require("../helpers/validate");
const jwt = require("jsonwebtoken")
const bcrypt = require('bcrypt')
const User = require("../models/user");
const Post = require("../models/post");
const { validateToken } = require("../helpers/token");
const { sendVerificationEmail, sendResetCode } = require("../helpers/mailer");
const Code = require("../models/code")
const generateCode = require("../helpers/generatecode")
exports.register = async (req, res) => {
    try {
        const {
            first_name,
            last_name,
            email,
            password,
            username,
            bYear,
            bMonth,
            bDay,
            gender
        } = req.body;
        if (!validateEmail(email)) {
            return res.status(400).json({
                message: "Invalid Email Address"
            });
        }
        const check = await User.findOne({ email });
        if (check) {
            return res.status(400).json({
                message: "Email already exists try with different email address"
            })
        }
        if (!validateLength(first_name, 3, 30)) {
            return res.status(400).json({
                message: "first name between 3 to 30 charectors"
            })
        }
        if (!validateLength(last_name, 3, 10)) {
            return res.status(400).json({
                message: "last name between 3 to 10 charectors"
            })
        }
        if (!validateLength(password, 6, 10)) {
            return res.status(400).json({
                message: "password between 6 charectors"
            })
        }
        const cryptpassword = await bcrypt.hash(password, 12)
        let tempusername = first_name + last_name;
        let newusername = await validateUsername(tempusername);
        const user = await new User({
            first_name,
            last_name,
            email,
            password: cryptpassword,
            username: newusername,
            bYear,
            bMonth,
            bDay,
            gender
        }).save();
        const verificationToken = validateToken({
            id: user._id.toString()
        },
            "30m"
        );
        const url = `${process.env.BASE_URL}/activate/${verificationToken}`;
        sendVerificationEmail(user.email, user.first_name, url);
        const token = validateToken({ id: user._id.toString() }, "7d");
        res.send({
            id: user._id,
            username: user.username,
            picture: user.picture,
            first_name: user.first_name,
            last_name: user.last_name,
            token: token,
            verified: user.verified,
            message: "Register Success ! please activate your email to start",
        });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }

};

exports.activateAccount = async (req, res) => {
    try {
        const validUser = req.user.id;
        const { token } = req.body
        const user = jwt.verify(token, process.env.TOKEN_SCRECT);
        const check = await User.findById(user.id)
        if (validUser !== user.id) {
            return res.status(400).json({ message: "you don't have Authenticated User" })
        }
        if (check.verified == true) {
            return res.status(400).json({ message: "this mail is already exists" })
        } else {
            await User.findByIdAndUpdate(user.id, { verified: true });
            return res
                .status(200)
                .json({ messsage: "Account has been Activated" })
        }
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
}
exports.login = async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: "The entered email address not connected to ur account." })
        }
        const check = await bcrypt.compare(password, user.password);
        if (!check) {
            return res.status(400).json({ message: "Invalid credentials, Please try again" })
        }
        const token = validateToken({ id: user._id.toString() }, "7d");
        res.send({
            id: user._id,
            username: user.username,
            picture: user.picture,
            first_name: user.first_name,
            last_name: user.last_name,
            token: token,
            verified: user.verified,
            message: "Register Success ! please activate your email to start",
        });

    } catch (error) {
        res.status(500).json({ message: error.message });
    }
}
exports.sendVerification = async (req, res) => {
    try {
        const id = req.user.id;
        const user = await User.findById(id);
        if (user.verified === true) {
            return res.status(400).json({
                message: "This account is already activated.",
            });
        }
        const verificationToken = validateToken({
            id: user._id.toString()
        },
            "30m"
        );
        const url = `${process.env.BASE_URL}/activate/${verificationToken}`;
        sendVerificationEmail(user.email, user.first_name, url);
        return res.status(200).json({
            message: "Email verification link has been sent to your email.",
        });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};
exports.findUser = async (req, res) => {
    try {
        const { email } = req.body
        const user = await User.findOne({ email }).select("-password")
        if (!user) {
            return res.status(400).json({
                message: "Account doesn't exists",
            })
        }
        return res.status(200).json({
            email: user.email,
            picture: user.picture
        })
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
}
exports.sendResetPasswordCode = async (req, res) => {
    try {
        const { email } = req.body
        const user = await User.findOne({ email }).select("-password")
        await Code.findOneAndRemove({ user: user._id })
        const code = generateCode(5)
        const savedcode = await new Code({
            code,
            user: user._id
        }).save();
        sendResetCode(user.email, user.first_name, code)
        return res.status(200).json({
            message: "email Reset code has been send to email"
        })
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
}
exports.validateResetCode = async (req, res) => {
    try {
        const { email, code } = req.body;
        console.log(code)
        const user = await User.findOne({ email });
        const Dbcode = await Code.findOne({
            user: user._id,
        });
        console.log(user._id)
        if (Dbcode.code !== code) {
            return res.status(400).json({
                message: "Verfication does't exists",
            })

        }
        return res.status(200).json({ message: "ok" });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};
exports.changepassword = async (req, res) => {
    const { email, password } = req.body
    const cryptPassword = await bcrypt.hash(password, 12)
    await User.findOneAndUpdate(
        { email },
        {
            password: cryptPassword
        }
    );
    return res.status(200).json({ message: "ok" })
}



exports.getProfile = async (req, res) => {
    try {
      const { username } = req.params;
      const user = await User.findById(req.user.id);
      const profile = await User.findOne({ username }).select("-password");
      const friendship = {
        friends: false,
        following: false,
        requestSent: false,
        requestReceived: false,
      };
     
      if (!profile) {
        return res.json({ ok: false });
      }
      if (
        user.friends.includes(profile._id) &&
        profile.friends.includes(user._id)
      ) {
        friendship.friends = true;
      }
      if (user.following.includes(profile._id)) {
        friendship.following = true;
      }
      if (user.requests.includes(profile._id)) {
        friendship.requestReceived = true;
      }
      if (profile.requests.includes(user._id)) {
        friendship.requestSent = true;
      }
      const posts = await Post.find({user :profile._id}).populate("user").sort({ createdAt: -1 });
      res.json({...profile.toObject(), posts});
    } catch (error) {
      res.status(500).json({ message: error.message });
    }
  };

  exports.updateProfilePicture = async (req, res) => {
    try {
      const { url } = req.body;
  
      await User.findByIdAndUpdate(req.user.id, {
        picture: url,
      });
      res.json(url);
    } catch (error) {
      res.status(500).json({ message: error.message });
    }
  };

  exports.updateCover = async (req, res) => {
    try {
      const { url } = req.body;
  
      await User.findByIdAndUpdate(req.user.id, {
        cover: url,
      });
      res.json(url);
    } catch (error) {
      res.status(500).json({ message: error.message });
    }
  };
  
  exports.updateDetails = async (req, res) => {
    try {
      const { infos } = req.body;
      const updated = await User.findByIdAndUpdate(
        req.user.id,
        {
          details: infos,
        },
        {
          new: true,
        }
      );
      res.json(updated.details);
    } catch (error) {
      res.status(500).json({ message: error.message });
    }
  };
  exports.addFriend = async (req, res) => {
    try {
        if(req.user.id !== req.params.id) {
            const sender = await User.findById(req.user.id);
            const receiver = await User.findById(req.params.id);
            if(
                !receiver.requests.includes(sender._id) && !receiver.friends.includes(sender._id)
            ) {
                await receiver.updateOne({
                    $push: { requests: sender._id },
                });
                await receiver.updateOne({
                    $push: { followers: sender._id },
                });
                await sender.updateOne({
                    $push: { following: sender._id },
                });
                res.json({ message: "friend request has been sent"});
            } else  {
                return res
                .status(400)
                .json({message: "Already sent"})
            }
        }else{
            return res
            .status(400)
            .json({message: "you can't send a request to yourself"})
        }
    } catch (error) {
      res.status(500).json({ message: error.message });
    }
  };
  exports.cancelRequest = async (req, res) => {
    try {
        if(req.user.id !== req.params.id) {
            const sender = await User.findById(req.user.id);
            const receiver = await User.findById(req.params.id);
            if(
                receiver.requests.includes(sender._id) && !receiver.friends.includes(sender._id)
            ) {
                await receiver.updateOne({
                    $pull: { requests: sender._id },
                });
                await receiver.updateOne({
                    $pull: { followers: sender._id },
                });
                await sender.updateOne({
                    $pull: { following: sender._id },
                });
                res.json({ message: "you successfully canceled request"});
            } else  {
                return res
                .status(400)
                .json({message: "Already canceled"})
            }
        }else{
            return res
            .status(400)
            .json({message: "you can't cancel a request to yourself"})
        }
    } catch (error) {
      res.status(500).json({ message: error.message });
    }
  };
  exports.follow = async (req, res) => {
    try {
        if(req.user.id !== req.params.id) {
            const sender = await User.findById(req.user.id);
            const receiver = await User.findById(req.params.id);
            if(
                !receiver.followers.includes(sender._id) && !sender.following.includes(receiver._id)
            ) {
                await receiver.updateOne({
                    $push: { followers: sender._id },
                });
                // await sender.updateOne({
                //     $push: { followers: receiver._id },  //oprional remove if it is not working
                // });
              
                await sender.updateOne({
                    $push: { following: sender._id },
                });
                res.json({ message: "follow success"});
            } else  {
                return res
                .status(400)
                .json({message: "Already following"})
            }
        }else{
            return res
            .status(400)
            .json({message: "you can't follow  yourself"})
        }
    } catch (error) {
      res.status(500).json({ message: error.message });
    }
  };
  exports.unfollow = async (req, res) => {
    try {
        if(req.user.id !== req.params.id) {
            const sender = await User.findById(req.user.id);
            const receiver = await User.findById(req.params.id);
            if(
                receiver.followers.includes(sender._id) && 
                sender.following.includes(receiver._id)
            ) {
                await receiver.updateOne({
                    $push: { followers: sender._id },
                });
                await sender.updateOne({
                    $pull: { following: receiver._id },  //optionla remove if it's not working
                });
                await sender.updateOne({
                    $pull: { following: sender._id },
                });
                res.json({ message: "unfollow success"});
            } else  {
                return res
                .status(400)
                .json({message: "Already  not following"})
            }
        }else{
            return res
            .status(400)
            .json({message: "you can't unfollow  yourself"})
        }
    } catch (error) {
      res.status(500).json({ message: error.message });
    }
  };
  exports.acceptRequest = async (req, res) => {
    try {
        if(req.user.id !== req.params.id) {
            const receiver = await User.findById(req.user.id);
            const sender = await User.findById(req.params.id);
            if(
                receiver.requests.includes(sender._id) 
            ) {
                await receiver.update({
                    $push: { friends: sender._id,following: sender._id },
                });            
                await sender.update({
                    $push: { friends: receiver._id,followers: receiver._id },
                });
                await receiver.updateOne({
                    $pull: { requests: sender._id },
                });
                res.json({ message: "friend requests accepted"});
            } else  {
                return res
                .status(400)
                .json({message: "Already  friends"})
            }
        }else{
            return res
            .status(400)
            .json({message: "you can't accept a request from  yourself"})
        }
    } catch (error) {
      res.status(500).json({ message: error.message });
    }
  };
  exports.unfriend = async (req, res) => {
    try {
      if (req.user.id !== req.params.id) {
        const sender = await User.findById(req.user.id);
        const receiver = await User.findById(req.params.id);
        if (
          receiver.friends.includes(sender._id) &&
          sender.friends.includes(receiver._id)
        ) {
          await receiver.update({
            $pull: {
              friends: sender._id,
              following: sender._id,
              followers: sender._id,
            },
          });
          await sender.update({
            $pull: {
              friends: receiver._id,
              following: receiver._id,
              followers: receiver._id,
            },
          });
  
          res.json({ message: "unfriend request accepted" });
        } else {
          return res.status(400).json({ message: "Already not friends" });
        }
      } else {
        return res.status(400).json({ message: "You can't unfriend yourself" });
      }
    } catch (error) {
      res.status(500).json({ message: error.message });
    }
  };
  exports.deleteRequest = async (req, res) => {
    try {
      if (req.user.id !== req.params.id) {
        const receiver = await User.findById(req.user.id);
        const sender = await User.findById(req.params.id);
        if (receiver.requests.includes(sender._id)) {
          await receiver.update({
            $pull: {
              requests: sender._id,
              followers: sender._id,
            },
          });
          await sender.update({
            $pull: {
              following: receiver._id,
            },
          });
  
          res.json({ message: "delete request accepted" });
        } else {
          return res.status(400).json({ message: "Already deleted" });
        }
      } else {
        return res.status(400).json({ message: "You can't delete yourself" });
      }
    } catch (error) {
      res.status(500).json({ message: error.message });
    }
  };
  