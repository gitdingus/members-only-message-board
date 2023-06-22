const express = require('express');
const userController = require('../controllers/userController.js');

const userRouter = express.Router();

userRouter.get('/:username/update-info', userController.get_update_info);
userRouter.post('/:username/update-info', userController.post_update_info);

userRouter.get('/:username/change-password', userController.get_change_password);
userRouter.post('/:username/change-password', userController.post_change_password);

userRouter.get('/:username/account-settings', userController.get_account_settings);
userRouter.post('/:username/account-settings', userController.post_account_settings);

userRouter.get('/:username/membership-status', userController.get_membership_status);
userRouter.post('/:username/membership-status', userController.post_membership_status);

userRouter.get('/:username/delete-account', userController.get_delete_account);
userRouter.post('/:username/delete-account', userController.post_delete_account);

userRouter.get('/:id/admin/delete_user_messages', userController.get_admin_delete_user_messages);
userRouter.post('/:id/admin/delete_user_messages', userController.post_admin_delete_user_messages);

userRouter.get('/:id/admin/set_user_status', userController.get_admin_set_user_status);
userRouter.post('/:id/admin/set_user_status', userController.post_admin_set_user_status);

userRouter.get('/:id/admin/delete_user', userController.get_admin_delete_user);
userRouter.post('/:id/admin/delete_user', userController.post_admin_delete_user);

userRouter.use('/:username', userController.get_user_details);

module.exports = userRouter;