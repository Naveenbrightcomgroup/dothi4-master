const express = require("express");
const {
  register,
  activateAccount,
  login,
  sendVerification,
  findUser,
  sendResetPasswordCode,
  validateResetCode,
  changepassword,getProfile,
  updateProfilePicture,
  updateCover,
  updateDetails,
  addFriend,
  cancelRequest,
  follow,
  unfollow,
  acceptRequest,
  unfriend,
  deleteRequest,
} = require("../controllers/user");
const { authUser } = require("../middlewares/auth");
const router = express.Router();
router.post("/register", register);
router.post("/activate", authUser, activateAccount);
router.post("/login", login);
router.post("/sendVerification", authUser, sendVerification);
router.post("/findUser", findUser);
router.post("/sendResetPasswordCode", sendResetPasswordCode);
router.post("/validateResetCode", validateResetCode);
router.post("/changepassword", changepassword);
router.get("/getProfile/:username", authUser, getProfile);
router.put("/updateProfilePicture", authUser, updateProfilePicture);
router.put("/updateCover", authUser, updateCover);
router.put("/updateDetails", authUser, updateDetails);
router.put("/addFriend/:id", addFriend);
router.put("/cancelRequest/:id", cancelRequest);
router.put("/follow/:id", follow);
router.put("/unfollow/:id", unfollow);
router.put("/acceptRequest/:id", acceptRequest);
router.put("/unfriend/:id",  unfriend);
router.put("/deleteRequest/:id", deleteRequest);
module.exports = router;
