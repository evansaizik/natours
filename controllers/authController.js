const crypto = require('crypto');
const { promisify } = require('util');
const jwt = require('jsonwebtoken');
const User = require('../model/userModel');
const AppError = require('../utils/appError');
const catchAsync = require('../utils/catchAsync');
const sendEmail = require('../utils/email');

const signToken = (id) =>
  jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: '10h',
  });

const createSendToken = (user, statusCode, res) => {
  const token = signToken(user._id);

  const cookieOptions = {
    expires: new Date(Date.now() + 10 * 60 * 60 * 1000),
    httpOnly: true,
  };
  if (process.env.NODE_ENV === 'production') cookieOptions.secure = true;

  res.cookie('jwt', token, cookieOptions);

  // remove the password from the output
  user.password = undefined;

  res.status(statusCode).json({
    status: 'success',
    token,
    data: {
      user,
    },
  });
};

exports.signup = catchAsync(async (req, res, next) => {
  const { name, email, photo, password, passwordConfirm, role } = req.body;
  const user = await User.findOne({ email: email });
  if (user) return next(new AppError('This user already exists', 409));

  const newUser = await User.create({
    name,
    email,
    photo,
    password,
    passwordConfirm,
    role,
  });

  createSendToken(newUser, 201, res);
});

exports.login = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;

  // Check if the email and password exists
  if (!email || !password) {
    return next(new AppError('Please provide email and password', 400));
  }
  //check if email and password is correct
  const existingUser = await User.findOne({ email }).select('+password');

  if (
    !existingUser ||
    !(await existingUser.correctPassword(password, existingUser.password))
  ) {
    return next(new AppError('Incorrect enail or password', 401));
  }

  createSendToken(existingUser, 200, res);
});

exports.protect = catchAsync(async (req, res, next) => {
  // Checking if the token exists
  let token;
  if (req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  } else
    return next(
      new AppError('You are not logged in, please login to get access', 401)
    );

  // verification token
  const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

  // check if the user still exists
  const existingUser = await User.findById(decoded.id).select('+password');
  if (!existingUser)
    return next(new AppError('This user no longer exists', 401));

  // check if the user changed password
  if (existingUser.changedPasswordAfter(decoded.iat))
    return next(
      new AppError('User recently changed password! Please log in again', 401)
    );

  // Grant access to protected route
  req.user = existingUser;

  next();
});

exports.restrictTo =
  (...roles) =>
  (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return next(
        new AppError('You do not have permission to perform this action', 403)
      );
    }

    next();
  };

exports.forgotPassword = async (req, res, next) => {
  // 1. Get user based on posted email
  const user = await User.findOne({ email: req.body.email });
  if (!user)
    return next(new AppError(`There's no user with this email address`, 404));

  // 2. Generate the random reset token
  const resetToken = user.createPasswordResetToken();
  await user.save({ validateBeforeSave: false });

  // 3. Send token to user's email
  const resetURL = `${req.protocol}://${req.get(
    'host'
  )}/api/v1/users/resetPassword/${resetToken}`;

  const message = `Forgot your password? Submit a PATCH request with your new password and passwordConfirm to : ${resetURL}. \nIf you didnt forget your password, please ignore this email`;

  try {
    await sendEmail({
      email: user.email,
      subject: 'Your password reset token (valid for 10 mins)',
      message,
    });

    res.status(200).json({
      status: 'success',
      message: 'Token sent to your email!',
    });
  } catch (error) {
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save({ validateBeforeSave: false });

    return next(
      new AppError('There was an error ssending the email. try again later')
    );
  }
};

exports.resetPassword = async (req, res, next) => {
  // 1. Get user based on the token
  const hashedToken = crypto
    .createHash('sha256')
    .update(req.params.token)
    .digest('hex');

  const user = await User.findOne({
    passwordResetToken: hashedToken,
    passwordResetExpires: { $gt: Date.now() },
  });

  // 2. if token has not expired, and if there's a user, set the new password
  if (!user) return next(new AppError('Token is invalid or has expired', 400));

  user.password = req.body.password;
  user.passwordConfirm = req.body.passwordConfirm;
  user.passwordResetExpires = undefined;
  user.passwordResetToken = undefined;
  await user.save();
  // 3. update the changedPasswordAt property for the user
  // 4. log the user in, send JWT
  createSendToken(user, 200, res);
};

exports.updatePassword = async (req, res, next) => {
  let token;
  const { password, newPassword, passwordConfirm } = req.body;
  // 1. Get the user from the collection
  if (req.headers.authorization.startsWith('Bearer'))
    token = req.headers.authorization.split(' ')[1];
  else
    return next(new AppError("You're not logged in, please login again", 401));
  const { id } = jwt.verify(token, process.env.JWT_SECRET);
  const user = await User.findById(id).select('+password');

  // 2. Check if the posted password is correct
  const isValid = await user.correctPassword(password, user.password);

  // 3. If so, update password
  if (isValid) {
    user.password = newPassword;
    user.passwordConfirm = passwordConfirm;
    user.save();
  } else return next(new AppError('Incorrect password', 401));

  // 4. Log user in, send jwt
  createSendToken(user, 200, res);
  // token = signToken(id);

  // res.status(200).json({
  //   status: 'success',
  //   token,
  // });
};
